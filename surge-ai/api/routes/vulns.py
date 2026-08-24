"""
Vulnerability routes:
  GET /vulnerabilities              — all vulns from latest completed scan
  GET /vulnerabilities?scan_id=...  — vulns from a specific scan
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, VulnerabilityModel, ScanModel
from api.models import VulnRecord

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnRecord])
async def list_vulnerabilities(
    scan_id: Optional[str] = Query(default=None, description="Filter by scan ID. Defaults to latest completed scan."),
    db: AsyncSession = Depends(get_db),
) -> list[VulnRecord]:

    if scan_id is None:
        # Prefer the most recently completed scan; fall back to latest running scan
        result = await db.execute(
            select(ScanModel)
            .where(ScanModel.status == "completed")
            .order_by(desc(ScanModel.completed_at))
            .limit(1)
        )
        latest = result.scalar_one_or_none()
        if not latest:
            result = await db.execute(
                select(ScanModel)
                .where(ScanModel.status == "running")
                .order_by(desc(ScanModel.created_at))
                .limit(1)
            )
            latest = result.scalar_one_or_none()
        if not latest:
            return []
        scan_id = latest.scan_id

    result = await db.execute(
        select(VulnerabilityModel)
        .where(VulnerabilityModel.scan_id == scan_id)
        .order_by(VulnerabilityModel.cvss_score_predicted.desc().nulls_last())
    )
    vulns = result.scalars().all()
    return [VulnRecord.model_validate(v) for v in vulns]
