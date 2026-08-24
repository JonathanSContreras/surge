"""
Dashboard routes:
  GET /dashboard/stats        — aggregate stats for the stat cards
  GET /dashboard/activity-feed — last N activity log entries
  GET /agents/status          — how many scans are currently running
  GET /topology               — network topology for the latest (or specified) completed scan
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, ScanModel, VulnerabilityModel, ActivityEventModel
from api.models import DashboardStats, ActivityEventRecord

logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

# Log line format from config/constants.py:
# "%(asctime)s [%(levelname)s] %(name)s/%(funcName)s >> %(message)s"
_LOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)"
    r"\s+\[(?P<level>\w+)\]\s+"
    r"(?P<logger>[^\s]+)/(?P<func>[^\s]+)\s+>>\s+"
    r"(?P<message>.+)"
)
_LEVEL_TO_TYPE = {
    "CRITICAL": "critical",
    "ERROR":    "critical",
    "WARNING":  "warning",
    "INFO":     "info",
    "DEBUG":    "info",
}


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    # Latest completed scan for device/vuln counts
    result = await db.execute(
        select(ScanModel)
        .where(ScanModel.status == "completed")
        .order_by(desc(ScanModel.completed_at))
        .limit(1)
    )
    latest = result.scalar_one_or_none()

    # Count running scans
    running_result = await db.execute(
        select(func.count()).select_from(ScanModel).where(ScanModel.status == "running")
    )
    active_count: int = running_result.scalar_one() or 0

    if not latest:
        return DashboardStats(
            devices_scanned=0,
            vulnerabilities_found=0,
            avg_cvss=None,
            active_scans=active_count,
        )

    return DashboardStats(
        devices_scanned=latest.devices_count or 0,
        vulnerabilities_found=latest.vulns_count or 0,
        avg_cvss=latest.avg_cvss,
        active_scans=active_count,
    )


@router.get("/dashboard/activity-feed", response_model=list[ActivityEventRecord])
async def get_activity_feed(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[ActivityEventRecord]:
    # Try DB first
    result = await db.execute(
        select(ActivityEventModel)
        .order_by(desc(ActivityEventModel.id))
        .limit(limit)
    )
    db_events = result.scalars().all()

    if db_events:
        return [ActivityEventRecord.model_validate(e) for e in db_events]

    # Fallback: tail the log file and parse it
    log_path = os.path.join(os.getcwd(), "log", "surge_log.log")
    if not os.path.exists(log_path):
        return []

    parsed: list[ActivityEventRecord] = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for i, line in enumerate(reversed(lines)):
            if len(parsed) >= limit:
                break
            m = _LOG_RE.match(line.strip())
            if not m:
                continue
            ts_str = m.group("ts").replace(",", ".")
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
            except ValueError:
                ts = datetime.now(timezone.utc)
            parsed.append(ActivityEventRecord(
                id=i,
                scan_id=None,
                event_type=_LEVEL_TO_TYPE.get(m.group("level"), "info"),
                message=m.group("message")[:500],
                detail=f"{m.group('logger')}/{m.group('func')}",
                ip=None,
                agent_node=None,
                created_at=ts,
            ))
    except OSError:
        logger.warning("Could not read log file at %s", log_path)

    return parsed


@router.get("/agents/status")
async def get_agents_status(
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(func.count()).select_from(ScanModel).where(ScanModel.status == "running")
    )
    active_count: int = result.scalar_one() or 0
    return {"active_count": active_count}


_EMPTY_TOPOLOGY: dict[str, Any] = {
    "hosts": [],
    "topology": {
        "nodes": [],
        "links": [],
        "metadata": {"total_nodes": 0, "total_links": 0, "has_trace_data": False, "gateway_ip": None},
    },
}


@router.get("/topology")
async def get_topology(
    scan_id: Optional[str] = Query(default=None, description="Specific scan ID. Defaults to latest completed scan."),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Returns the raw dashboard_data.json payload: { hosts, topology }.
    When no scan_id is given, prefers an actively running scan (so the live
    dashboard updates as the pipeline writes intermediate snapshots) and falls
    back to the most recent completed scan when nothing is running.
    """
    if scan_id is None:
        # Prefer a running scan — serves intermediate snapshots as they are written
        result = await db.execute(
            select(ScanModel)
            .where(ScanModel.status == "running")
            .order_by(desc(ScanModel.created_at))
            .limit(1)
        )
        scan = result.scalar_one_or_none()

        # No active scan — fall back to the latest completed one
        if not scan:
            result = await db.execute(
                select(ScanModel)
                .where(ScanModel.status == "completed")
                .order_by(desc(ScanModel.completed_at))
                .limit(1)
            )
            scan = result.scalar_one_or_none()
    else:
        result = await db.execute(select(ScanModel).where(ScanModel.scan_id == scan_id))
        scan = result.scalar_one_or_none()

    if not scan or not scan.run_dir:
        return _EMPTY_TOPOLOGY

    dashboard_path = os.path.join(scan.run_dir, "dashboard_data.json")
    if not os.path.exists(dashboard_path):
        # Running scan hasn't written its first snapshot yet — return empty so
        # the frontend shows a blank slate rather than the previous scan's data.
        return _EMPTY_TOPOLOGY

    with open(dashboard_path, "r", encoding="utf-8") as f:
        return json.load(f)
