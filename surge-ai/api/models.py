"""
Pydantic request/response schemas for the Surge API.
These are the shapes that cross the HTTP boundary — kept separate from the
SQLAlchemy ORM models in db.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

ScanTypeIn  = Literal["quick", "normal", "deep", "stealth"]   # dashboard vocabulary
ScanStatus  = Literal["running", "completed", "failed"]
AgentMode   = Literal["manual", "autonomous"]

# quick → low, normal → medium, deep → high, stealth → medium
SCAN_TYPE_MAP: dict[str, str] = {
    "quick":   "low",
    "normal":  "medium",
    "deep":    "high",
    "stealth": "medium",
}


class ScanRenameBody(BaseModel):
    name: str


class ScanRequest(BaseModel):
    name:       Optional[str]      = Field(default=None, description="Human-readable label for this scan.")
    target:     Optional[str]      = Field(default=None, examples=["10.10.160.0/24"],
                                           description="CIDR target. Omit to auto-detect via ARP/gateway.")
    scan_type:  ScanTypeIn         = Field(default="normal")
    agent_mode: AgentMode          = Field(default="autonomous")


class ScanRecord(BaseModel):
    scan_id:       str
    name:          Optional[str]
    target_range:  str
    scan_type:     ScanTypeIn
    status:        ScanStatus
    devices_count: int
    vulns_count:   int
    avg_cvss:      Optional[float]
    created_at:    datetime
    completed_at:  Optional[datetime]
    duration_s:    Optional[float]

    model_config = {"from_attributes": True}


class ScanCreatedResponse(BaseModel):
    scan_id: str
    status:  ScanStatus


# ---------------------------------------------------------------------------
# WebSocket — scan progress events
# ---------------------------------------------------------------------------

class AgentEvent(BaseModel):
    node:      str
    message:   str
    timestamp: str


class ScanProgressEvent(BaseModel):
    scan_id:         str
    status:          ScanStatus
    progress:        int           # 0–100
    elapsed_seconds: float
    events:          list[AgentEvent]


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

DeviceStatus   = Literal["online", "offline", "scanning"]
Severity       = Literal["low", "medium", "high", "critical"]


class DeviceRecord(BaseModel):
    id:          int
    scan_id:     str
    ip:          str
    hostname:    Optional[str]
    device_type: Optional[str]
    os_name:     Optional[str]
    description: Optional[str]
    status:      DeviceStatus
    severity:    Severity
    cvss_score:  float
    subnet:      Optional[str]

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

ExploitAvailability = Literal["public", "private", "none"]
VulnStatus          = Literal["queued", "in_progress", "exploited", "patched"]


class VulnRecord(BaseModel):
    id:                       int
    scan_id:                  str
    cve_id:                   str
    affected_device_ip:       str
    affected_device_hostname: Optional[str]
    product:                  Optional[str]
    version:                  Optional[str]
    cvss_score_raw:           Optional[float]
    cvss_score_predicted:     Optional[float]
    severity:                 Optional[str]
    summary:                  Optional[str]
    exploitable:              Optional[bool]
    remediation:              Optional[str]
    exploit_availability:     ExploitAvailability
    status:                   VulnStatus

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    devices_scanned:      int
    vulnerabilities_found: int
    avg_cvss:             Optional[float]
    active_scans:         int


# ---------------------------------------------------------------------------
# Activity feed
# ---------------------------------------------------------------------------

ActivityEventType = Literal["info", "warning", "critical", "patch", "exploit", "success"]

class ActivityEventRecord(BaseModel):
    id:         int
    scan_id:    Optional[str]
    event_type: ActivityEventType
    message:    str
    detail:     Optional[str]
    ip:         Optional[str]
    agent_node: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportTemplate(BaseModel):
    id:          str
    name:        str
    description: str


class ReportGenerateRequest(BaseModel):
    template_id: str
    scan_id:     str


class RiskMatrix(BaseModel):
    critical: int
    high:     int
    medium:   int
    low:      int


class ReportRecord(BaseModel):
    id:                str
    scan_id:           str
    template_id:       str
    created_at:        datetime
    raw_markdown:      Optional[str]
    executive_summary: Optional[str]
    scope:             Optional[str]
    methodology:       Optional[str]
    key_findings:      Optional[str]
    recommendations:   Optional[str]
    risk_matrix:       RiskMatrix

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

class ScanProfileRecord(BaseModel):
    id:         int
    name:       str
    target:     str
    scan_type:  ScanTypeIn
    created_at: datetime

    model_config = {"from_attributes": True}
