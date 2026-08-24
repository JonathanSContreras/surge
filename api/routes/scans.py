"""
Scan routes:
  POST   /scans                    — launch a scan
  GET    /scans                    — list all scans
  GET    /scans/{scan_id}          — single scan record
  WebSocket /ws/scans/{scan_id}    — real-time progress stream
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, ScanModel, DeviceModel, VulnerabilityModel, ActivityEventModel
from api.models import (
    ScanRequest, ScanRecord, ScanCreatedResponse,
    ScanProgressEvent, AgentEvent, ScanRenameBody,
    SCAN_TYPE_MAP,
)
from utils.helpers import score_conversion

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory event queues keyed by scan_id — used to bridge the background
# thread running graph.stream() to the WebSocket handler.
_scan_queues: dict[str, asyncio.Queue] = {}

# Node → approximate progress percentage
NODE_PROGRESS: dict[str, int] = {
    "recon":              15,
    "recon_analyzer":     30,
    "os_finder":          30,
    "os_analyzer":        45,
    "vulnerability":      65,
    "cvss_data_formatter": 75,
    "cvss_scoring":       85,
    "reporter":           100,
}

# Node → (human-readable message, event_type)
NODE_MESSAGES: dict[str, tuple[str, str]] = {
    "recon":               ("Network reconnaissance complete",                "info"),
    "recon_analyzer":      ("Device map built from recon results",            "info"),
    "os_finder":           ("OS fingerprinting complete",                     "info"),
    "os_analyzer":         ("Operating systems identified",                   "info"),
    "vulnerability":       ("Vulnerability scan complete",                    "warning"),
    "cvss_data_formatter": ("CVE data formatted and normalized",              "info"),
    "cvss_scoring":        ("Vulnerabilities scored with ML model",           "warning"),
    "reporter":            ("Network Security Assessment report written",      "info"),
}


async def _emit_activity(
    scan_id: str,
    message: str,
    event_type: str = "info",
    detail: str | None = None,
    ip: str | None = None,
    agent_node: str | None = None,
) -> None:
    """Write a single activity event row to the DB."""
    from api.db import AsyncSessionLocal, ActivityEventModel
    async with AsyncSessionLocal() as session:
        session.add(ActivityEventModel(
            scan_id=scan_id,
            event_type=event_type,
            message=message,
            detail=detail,
            ip=ip,
            agent_node=agent_node,
        ))
        await session.commit()


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _run_scan_background(
    scan_id: str,
    initial_state: dict,
    db_url: str,
) -> None:
    """
    Launched via BackgroundTasks.  Uses graph.astream() so each completed node
    immediately pushes a progress event into the per-scan asyncio Queue — no
    thread-pool bridging needed, no race condition on final_state.

    LangGraph wraps synchronous node functions in asyncio.to_thread() internally,
    so blocking nmap / XGBoost work never stalls the FastAPI event loop.
    """
    from workflow.graph import build_mas_graph
    from api.db import AsyncSessionLocal, ScanModel, DeviceModel, VulnerabilityModel
    from api.activity import set_scan_context

    queue: asyncio.Queue = asyncio.Queue()
    _scan_queues[scan_id] = queue

    set_scan_context(scan_id)
    graph = build_mas_graph()
    start = time.time()

    # Track final state locally — avoids the race where WebSocket handler
    # drains the queue before we read "done" out of it.
    final_state: dict[str, Any] = dict(initial_state)
    elapsed = 0.0
    error_msg: str | None = None

    await _emit_activity(scan_id, "Scan started", event_type="info", agent_node="system")

    try:
        async for event in graph.astream(initial_state):
            node_name = list(event.keys())[0]
            final_state.update(event[node_name] or {})
            elapsed = round(time.time() - start, 1)

            if node_name == "cvss_scoring":
                vuln_count = len(final_state.get("vuln_scoring", []) or [])
                msg = f"Vulnerabilities scored with ML model — {vuln_count} CVEs processed"
                etype = "warning"
            else:
                msg, etype = NODE_MESSAGES.get(node_name, (f"{node_name} completed", "info"))
            await _emit_activity(scan_id, msg, event_type=etype, agent_node=node_name)

            await queue.put({
                "type": "progress",
                "progress": NODE_PROGRESS.get(node_name, 0),
                "elapsed_seconds": elapsed,
                "events": [{
                    "node": node_name,
                    "message": msg,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }],
            })
        elapsed = round(time.time() - start, 1)
        await queue.put({"type": "done", "elapsed_seconds": elapsed})
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        error_msg = str(exc)
        elapsed = round(time.time() - start, 1)
        await _emit_activity(scan_id, f"Scan failed: {exc}", event_type="critical", agent_node="system")
        await queue.put({"type": "error", "message": error_msg})

    # Persist results to DB
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                _scan_queues.pop(scan_id, None)
                return

            now = datetime.now(timezone.utc)

            if error_msg:
                scan.status = "failed"
                scan.error_message = error_msg
                scan.completed_at = now
                scan.duration_s = elapsed
                await session.commit()
                _scan_queues.pop(scan_id, None)
                return

            # Persist devices
            hosts: list[dict] = []
            dashboard_path = os.path.join(final_state.get("run_dir", ""), "dashboard_data.json")
            if os.path.exists(dashboard_path):
                with open(dashboard_path) as f:
                    raw = json.load(f)
                    hosts = raw if isinstance(raw, list) else raw.get("hosts", [])

            device_ip_to_id: dict[str, int] = {}
            for h in hosts:
                ip = h.get("ip", "")
                dev = DeviceModel(
                    scan_id=scan_id,
                    ip=ip,
                    hostname=None if h.get("hostname") in ("idk", None, "") else h["hostname"],
                    device_type=None if h.get("deviceType") in ("idk", None, "") else h["deviceType"],
                    description=h.get("description"),
                    status="online" if h.get("status") == "up" else "offline",
                    severity=h.get("severity", "low"),
                    cvss_score=h.get("cvss", 0.0),
                )
                session.add(dev)
                await session.flush()
                device_ip_to_id[ip] = dev.id

            # Persist vulnerabilities
            vuln_scoring: list[dict] = final_state.get("vuln_scoring", [])
            if isinstance(vuln_scoring, dict):
                vuln_scoring = list(vuln_scoring.values())

            for v in vuln_scoring:
                ip = v.get("host", v.get("ip", ""))
                predicted = v.get("predicted_score")
                raw_cvss = v.get("cvss_score") or v.get("cvss")
                exploitable = v.get("exploitable", False)
                vuln = VulnerabilityModel(
                    scan_id=scan_id,
                    device_id=device_ip_to_id.get(ip),
                    cve_id=v.get("cve_id", "UNKNOWN"),
                    affected_device_ip=ip,
                    affected_device_hostname=v.get("hostname"),
                    product=v.get("product"),
                    version=v.get("version"),
                    cvss_score_raw=raw_cvss,
                    cvss_score_predicted=predicted,
                    severity=score_conversion(predicted) if predicted is not None else None,
                    summary=v.get("summary"),
                    exploitable=exploitable,
                    remediation=v.get("remediation"),
                    exploit_availability="public" if exploitable else "none",
                    access_authentication=v.get("access_authentication"),
                    access_complexity=v.get("access_complexity"),
                    access_vector=v.get("access_vector"),
                    impact_availability=v.get("impact_availability"),
                    impact_confidentiality=v.get("impact_confidentiality"),
                    impact_integrity=v.get("impact_integrity"),
                    cwe_code=str(v.get("cwe_code")) if v.get("cwe_code") else None,
                    cwe_name=v.get("cwe_name"),
                )
                session.add(vuln)

            # Update scan aggregate stats
            scores = [v.get("predicted_score") for v in vuln_scoring if v.get("predicted_score") is not None]
            scan.status = "completed"
            scan.completed_at = now
            scan.duration_s = elapsed
            scan.devices_count = len(hosts)
            scan.vulns_count = len(vuln_scoring)
            scan.avg_cvss = round(sum(scores) / len(scores), 2) if scores else None
            scan.run_dir = final_state.get("run_dir")

            session.add(ActivityEventModel(
                scan_id=scan_id,
                event_type="info",
                message=f"Scan complete — {len(hosts)} devices, {len(vuln_scoring)} vulnerabilities found",
                agent_node="system",
            ))

            await session.commit()

    except Exception as exc:
        logger.exception("Scan %s — DB persistence failed after scan completed", scan_id)
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
            scan = result.scalar_one_or_none()
            if scan and scan.status == "running":
                scan.status = "failed"
                scan.error_message = f"DB persistence error: {exc}"
                scan.completed_at = datetime.now(timezone.utc)
                scan.duration_s = elapsed
                await session.commit()

    finally:
        _scan_queues.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanCreatedResponse, status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ScanCreatedResponse:
    agent_scan_type = SCAN_TYPE_MAP[request.scan_type]

    # Resolve targets — explicit CIDR or auto-detect via ARP/gateway
    if request.target:
        targets = [request.target]
        target_range = request.target
    else:
        from execution.address_grab import build_initial_target_lists
        loop = asyncio.get_running_loop()
        detected = await loop.run_in_executor(None, build_initial_target_lists)
        targets = detected["targets"]
        target_range = ", ".join(targets)
        logger.info("Auto-detected targets: %s", target_range)

    scan_id = str(uuid4())
    run_dir = f"./report/{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{scan_id[:8]}"
    os.makedirs(run_dir, exist_ok=True)

    auto_name = request.name or f"{request.scan_type.capitalize()} Scan — {target_range}"
    scan = ScanModel(
        scan_id=scan_id,
        name=auto_name,
        target_range=target_range,
        scan_type=request.scan_type,
        agent_scan_type=agent_scan_type,
        agent_mode=request.agent_mode,
        status="running",
        run_dir=run_dir,
    )
    db.add(scan)
    await db.commit()

    initial_state = {
        "scan_type": agent_scan_type,
        "targets": targets,
        "run_dir": run_dir,
        "recon_results": {},
        "all_xml_content": "",
        "recon_analysis": "",
        "os_fingerprint_results": {},
        "os_xml_content": "",
        "os_analysis": "",
        "vuln_raw_results": [],
        "vuln_normalized_results": [],
        "vuln_scoring": {},
        "network_findings": "",
    }

    background_tasks.add_task(_run_scan_background, scan_id, initial_state, "")

    return ScanCreatedResponse(scan_id=scan_id, status="running")


@router.get("", response_model=list[ScanRecord])
async def list_scans(
    db: AsyncSession = Depends(get_db),
) -> list[ScanRecord]:
    result = await db.execute(select(ScanModel).order_by(desc(ScanModel.created_at)))
    scans = result.scalars().all()
    return [ScanRecord.model_validate(s) for s in scans]


@router.post("/{scan_id}/stop", status_code=200)
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    now = datetime.now(timezone.utc)
    scan.status = "failed"
    scan.error_message = "Stopped by user"
    scan.completed_at = now
    scan.duration_s = (now - scan.created_at.replace(tzinfo=timezone.utc)).total_seconds() if scan.created_at else None

    db.add(ActivityEventModel(
        scan_id=scan_id,
        event_type="warning",
        message="Scan stopped by user",
        agent_node="system",
    ))
    await db.commit()

    # Signal the WebSocket handler to close
    queue = _scan_queues.get(scan_id)
    if queue:
        await queue.put({"type": "error", "message": "Stopped by user"})

    return {"scan_id": scan_id, "status": "failed"}


@router.get("/{scan_id}", response_model=ScanRecord)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanRecord:
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRecord.model_validate(scan)


@router.patch("/{scan_id}", response_model=ScanRecord)
async def rename_scan(
    scan_id: str,
    body: ScanRenameBody,
    db: AsyncSession = Depends(get_db),
) -> ScanRecord:
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.name = body.name.strip() or None
    await db.commit()
    return ScanRecord.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    await db.delete(scan)
    await db.commit()


# ---------------------------------------------------------------------------
# WebSocket — progress stream
# ---------------------------------------------------------------------------

@router.websocket("/ws/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    await websocket.accept()

    # Confirm the scan exists
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        await websocket.send_json({"error": f"Scan {scan_id} not found"})
        await websocket.close()
        return

    # If already done, send current status immediately
    if scan.status in ("completed", "failed"):
        await websocket.send_json({
            "scan_id": scan_id,
            "status": scan.status,
            "progress": 100 if scan.status == "completed" else 0,
            "elapsed_seconds": scan.duration_s or 0.0,
            "events": [],
        })
        await websocket.close()
        return

    queue = _scan_queues.get(scan_id)

    try:
        while True:
            if queue:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    # Send a heartbeat so the client knows we're alive
                    await websocket.send_json({"type": "heartbeat", "scan_id": scan_id})
                    continue

                if msg.get("type") == "progress":
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "status": "running",
                        "progress": msg["progress"],
                        "elapsed_seconds": msg["elapsed_seconds"],
                        "events": msg["events"],
                    })
                elif msg.get("type") in ("done", "error"):
                    status = "completed" if msg["type"] == "done" else "failed"
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "status": status,
                        "progress": 100 if status == "completed" else 0,
                        "elapsed_seconds": msg.get("elapsed_seconds", 0.0),
                        "events": [],
                    })
                    break
            else:
                # Queue not yet created or already cleaned up — poll DB
                await asyncio.sleep(3)
                await db.refresh(scan)
                if scan.status in ("completed", "failed"):
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "status": scan.status,
                        "progress": 100 if scan.status == "completed" else 0,
                        "elapsed_seconds": scan.duration_s or 0.0,
                        "events": [],
                    })
                    break

    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
