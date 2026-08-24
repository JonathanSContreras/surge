"""
Report routes:
  GET  /reports/templates        — list available report templates
  POST /reports/generate         — load a pre-generated report .md file into the DB
  GET  /reports/{report_id}      — fetch a generated report
  GET  /reports?scan_id=...      — list reports for a scan
"""

from __future__ import annotations

import logging
import os
import re
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, ScanModel, ReportModel, VulnerabilityModel
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

# Maps template id → the filename written by reporter.py
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


@router.post("/generate", response_model=ReportRecord, status_code=201)
async def generate_report(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
) -> ReportRecord:
    # Validate scan exists and is completed
    result = await db.execute(select(ScanModel).where(ScanModel.scan_id == request.scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is not completed (status: {scan.status})")

    # Resolve which .md file to read for this template; fall back to final_report.md
    filename = _TEMPLATE_FILES.get(request.template_id, "final_report.md")
    run_dir = scan.run_dir or ""
    report_path = os.path.join(run_dir, filename) if run_dir else None
    fallback_path = os.path.join(run_dir, "final_report.md") if run_dir else None

    raw_markdown: str | None = None
    resolved: dict[str, str | None] = {f: None for f in _FIELD_ALIASES}

    path_to_try = None
    if report_path and os.path.exists(report_path):
        path_to_try = report_path
    elif fallback_path and os.path.exists(fallback_path):
        logger.warning("%s not found — falling back to final_report.md", filename)
        path_to_try = fallback_path
    else:
        logger.warning("No report file found at %s or %s", report_path, fallback_path)

    if path_to_try:
        with open(path_to_try, "r", encoding="utf-8") as f:
            raw_markdown = f.read()
        resolved = _resolve_sections(_parse_markdown_sections(raw_markdown))

    # Compute risk matrix from vulnerabilities table
    vuln_result = await db.execute(
        select(VulnerabilityModel).where(VulnerabilityModel.scan_id == request.scan_id)
    )
    vulns = vuln_result.scalars().all()
    risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = (v.severity or "low").lower()
        if sev in risk:
            risk[sev] += 1

    report_id = str(uuid4())
    report = ReportModel(
        id=report_id,
        scan_id=request.scan_id,
        template_id=request.template_id,
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
        risk_matrix=RiskMatrix(**risk),
    )


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
