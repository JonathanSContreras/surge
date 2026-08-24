"""
Report routes:
  GET  /reports/templates        — list available report templates
  POST /reports/generate         — load a pre-generated report .md file into the DB
  GET  /reports/{report_id}      — fetch a generated report
  GET  /reports?scan_id=...      — list reports for a scan
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, ScanModel, ReportModel, VulnerabilityModel, ActivityEventModel
from agents.prompts import (
    EXECUTIVE_REPORT_SYSTEM_PROMPT,
    TECHNICAL_REPORT_SYSTEM_PROMPT,
    PUBLIC_REPORT_SYSTEM_PROMPT,
)
from api.models import (
    ReportTemplate,
    ReportGenerateRequest,
    ReportRecord,
    RiskMatrix,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])

TEMPLATES: list[ReportTemplate] = [
    ReportTemplate(id="executive",  name="Executive Report",   description="Risk posture, financial impact, and exploit exposure for CEO/Board/Stakeholders"),
    ReportTemplate(id="technical",  name="Technical Report",   description="Exploitation detail, coverage gaps, and remediation steps for the CISO"),
    ReportTemplate(id="public",     name="Public Facing",      description="High-level, non-sensitive posture summary for press briefings and newsletters"),
    ReportTemplate(id="final",      name="Final Report",       description="Complete combined report — all sections from all perspectives"),
]

# Maps template id → the system prompt used to generate it on demand.
# "final" is absent deliberately: it is produced by the reporter agent during
# the scan and is the source material every other template is derived from.
_SPECIALIZED_PROMPTS: dict[str, str] = {
    "executive": EXECUTIVE_REPORT_SYSTEM_PROMPT,
    "technical": TECHNICAL_REPORT_SYSTEM_PROMPT,
    "public":    PUBLIC_REPORT_SYSTEM_PROMPT,
}

_SPECIALIZED_PREFIX = (
    "Below is the complete Network Security Assessment Report.\n"
    "Generate the specialized report now using ONLY this information.\n\n"
    "---\n\n"
)

# Maps template id → the filename written into the scan's run_dir
_TEMPLATE_FILES: dict[str, str] = {
    "executive": "executive_report.md",
    "technical": "technical_report.md",
    "public":    "public_report.md",
    "final":     "final_report.md",
}


def _parse_markdown_sections(markdown: str) -> dict[str, str]:
    """Split a report .md file into sections by ## headings."""
    sections: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []

    def _key(heading: str) -> str:
        # Strip a leading enumerator first. The reporter prompt yields numbered
        # headings ("## 1. Executive Summary"), which keyed to
        # "1_executive_summary" and matched no alias — so every section field
        # came back NULL and the Reports page rendered blank panels with only
        # raw_markdown populated.
        heading = re.sub(r"^\s*\d+\s*[.)\-:]?\s*", "", heading)
        return re.sub(r"[^a-z0-9]+", "_", heading.lower()).strip("_")

    for line in markdown.splitlines():
        if line.startswith("## "):
            if current_key:
                sections[current_key] = "\n".join(current_lines).strip()
            current_key = _key(line[3:])
            current_lines = []
        elif current_key is not None:
            current_lines.append(line)

    if current_key:
        sections[current_key] = "\n".join(current_lines).strip()

    return sections


# Priority-ordered aliases for each canonical field.
# The first alias found in the parsed sections wins.
_FIELD_ALIASES: dict[str, list[str]] = {
    "executive_summary": [
        "executive_summary",
        "technical_executive_summary",
        "overview",
        "summary",
    ],
    "scope": [
        "scope",
        "attack_surface_overview",
        "what_we_did",
        "technical_overview",
        "assessment_scope",
        "exposed_business_assets",
    ],
    "methodology": [
        "methodology",
        "scan_methodology",
        "risk_metrics",
        "operating_system_analysis",
        "what_we_did",
    ],
    "key_findings": [
        "key_findings",
        "key_findings_business_language",
        "vulnerability_findings",
        "vulnerability_findings_host_correlated",
        "what_we_found",
        "coverage_gaps",
    ],
    "recommendations": [
        "recommendations",
        "strategic_recommendations",
        "prioritized_remediation_roadmap",
        "remediation_recommendations",
        "what_we_are_doing_about_it",
        "remediation_roadmap",
    ],
}


def _resolve_sections(raw_sections: dict[str, str]) -> dict[str, str | None]:
    """Map raw parsed keys → canonical field names using aliases."""
    out: dict[str, str | None] = {field: None for field in _FIELD_ALIASES}
    for field, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in raw_sections:
                out[field] = raw_sections[alias]
                break
    return out


@router.get("/templates", response_model=list[ReportTemplate])
async def list_templates() -> list[ReportTemplate]:
    return TEMPLATES


def _generate_specialized_sync(template_id: str, final_markdown: str) -> str | None:
    """Blocking LLM call. Callers must run this off the event loop."""
    from core.llm import get_llm
    from langchain.schema import SystemMessage, HumanMessage

    llm = get_llm(tier="analysis")
    try:
        resp = llm.invoke([
            SystemMessage(content=_SPECIALIZED_PROMPTS[template_id]),
            HumanMessage(content=_SPECIALIZED_PREFIX + final_markdown),
        ])
    except Exception:
        logger.exception("LLM failed generating '%s' report", template_id)
        return None
    content = getattr(resp, "content", None)
    return content.strip() if isinstance(content, str) and content.strip() else None


async def _resolve_markdown(scan: ScanModel, template_id: str) -> str | None:
    """
    Return the markdown for this template, generating it if it doesn't exist yet.

    The reporter agent only writes final_report.md during a scan. The executive,
    technical and public variants are produced here the first time they're asked
    for, then cached as .md in the same run_dir so a second request is free.
    """
    run_dir = scan.run_dir or ""
    if not run_dir:
        logger.warning("Scan %s has no run_dir — cannot resolve report", scan.scan_id)
        return None

    path = os.path.join(run_dir, _TEMPLATE_FILES.get(template_id, "final_report.md"))
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    final_path = os.path.join(run_dir, "final_report.md")
    if not os.path.exists(final_path):
        logger.warning("No final_report.md at %s — nothing to derive from", final_path)
        return None
    with open(final_path, "r", encoding="utf-8") as f:
        final_markdown = f.read()

    if template_id not in _SPECIALIZED_PROMPTS:
        return final_markdown          # 'final' itself, or an unknown id

    # Generate off the event loop — llm.invoke() blocks.
    content = await asyncio.to_thread(_generate_specialized_sync, template_id, final_markdown)
    if not content:
        logger.warning("Generation of '%s' returned empty — falling back to final report", template_id)
        return final_markdown

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError:
        logger.exception("Could not cache %s (report still returned)", path)
    return content


async def persist_report(db: AsyncSession, scan: ScanModel, template_id: str) -> ReportModel:
    """
    Build and store one report row. Shared by POST /reports/generate and by
    scan completion in api/routes/scans.py, so a scheduled scan lands in the
    Reports tab without anyone clicking Generate.
    """
    raw_markdown = await _resolve_markdown(scan, template_id)
    resolved: dict[str, str | None] = {f: None for f in _FIELD_ALIASES}
    if raw_markdown:
        resolved = _resolve_sections(_parse_markdown_sections(raw_markdown))

    vuln_result = await db.execute(
        select(VulnerabilityModel).where(VulnerabilityModel.scan_id == scan.scan_id)
    )
    risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vuln_result.scalars().all():
        sev = (v.severity or "low").lower()
        if sev in risk:
            risk[sev] += 1

    report = ReportModel(
        id=str(uuid4()),
        scan_id=scan.scan_id,
        template_id=template_id,
        raw_markdown=raw_markdown,
        executive_summary=resolved["executive_summary"],
        scope=resolved["scope"],
        methodology=resolved["methodology"],
        key_findings=resolved["key_findings"],
        recommendations=resolved["recommendations"],
        risk_critical=risk["critical"],
        risk_high=risk["high"],
        risk_medium=risk["medium"],
        risk_low=risk["low"],
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


def _to_record(report: ReportModel) -> ReportRecord:
    return ReportRecord(
        id=report.id,
        scan_id=report.scan_id,
        template_id=report.template_id,
        created_at=report.created_at,
        raw_markdown=report.raw_markdown,
        executive_summary=report.executive_summary,
        scope=report.scope,
        methodology=report.methodology,
        key_findings=report.key_findings,
        recommendations=report.recommendations,
        risk_matrix=RiskMatrix(
            critical=report.risk_critical, high=report.risk_high,
            medium=report.risk_medium,     low=report.risk_low,
        ),
    )


@router.post("/generate", response_model=ReportRecord, status_code=201)
async def generate_report(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
) -> ReportRecord:
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == request.scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is not completed (status: {scan.status})")

    name = next((t.name for t in TEMPLATES if t.id == request.template_id), request.template_id)
    db.add(ActivityEventModel(
        scan_id=request.scan_id, event_type="info", agent_node="reporter",
        message=f"Generating {name} for scan {request.scan_id[:8]}",
    ))
    await db.commit()

    report = await persist_report(db, scan, request.template_id)

    db.add(ActivityEventModel(
        scan_id=request.scan_id, event_type="success", agent_node="reporter",
        message=f"{name} ready — scan {request.scan_id[:8]}",
    ))
    await db.commit()
    return _to_record(report)


@router.get("", response_model=list[ReportRecord])
async def list_reports(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[ReportRecord]:
    query = select(ReportModel)
    if scan_id:
        query = query.where(ReportModel.scan_id == scan_id)
    result = await db.execute(query)
    reports = result.scalars().all()

    out = []
    for r in reports:
        out.append(ReportRecord(
            id=r.id,
            scan_id=r.scan_id,
            template_id=r.template_id,
            created_at=r.created_at,
            raw_markdown=r.raw_markdown,
            executive_summary=r.executive_summary,
            scope=r.scope,
            methodology=r.methodology,
            key_findings=r.key_findings,
            recommendations=r.recommendations,
            risk_matrix=RiskMatrix(
                critical=r.risk_critical,
                high=r.risk_high,
                medium=r.risk_medium,
                low=r.risk_low,
            ),
        ))
    return out


@router.get("/{report_id}", response_model=ReportRecord)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
) -> ReportRecord:
    result = await db.execute(select(ReportModel).where(ReportModel.id == report_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportRecord(
        id=r.id,
        scan_id=r.scan_id,
        template_id=r.template_id,
        created_at=r.created_at,
        raw_markdown=r.raw_markdown,
        executive_summary=r.executive_summary,
        scope=r.scope,
        methodology=r.methodology,
        key_findings=r.key_findings,
        recommendations=r.recommendations,
        risk_matrix=RiskMatrix(
            critical=r.risk_critical,
            high=r.risk_high,
            medium=r.risk_medium,
            low=r.risk_low,
        ),
    )
