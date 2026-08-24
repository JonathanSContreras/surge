"""
Device routes:
  GET /devices              — all devices from latest completed scan
  GET /devices?scan_id=...  — devices from a specific scan
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db, DeviceModel, ScanModel
from api.models import DeviceRecord

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceRecord])
async def list_devices(
    scan_id: Optional[str] = Query(default=None, description="Filter by scan ID. Defaults to latest completed scan."),
    db: AsyncSession = Depends(get_db),
) -> list[DeviceRecord]:

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
        select(DeviceModel)
        .where(DeviceModel.scan_id == scan_id)
        .order_by(DeviceModel.cvss_score.desc())
    )
    devices = result.scalars().all()
    return [DeviceRecord.model_validate(d) for d in devices]
