"""
Database setup — SQLAlchemy async engine, session factory, and ORM models.

Uses PostgreSQL in production (DATABASE_URL=postgresql+asyncpg://...)
Falls back to SQLite for local dev (DATABASE_URL=sqlite+aiosqlite:///./surge.db)
"""

import os
from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./surge.db"   # local dev default
)

# PostgreSQL uses JSONB; SQLite uses Text — handled via String fallback below
_is_postgres = DATABASE_URL.startswith("postgresql")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    # Postgres is local, but a multi-hour Deep scan can still idle a pooled
    # connection long enough for it to be dropped. Cheap insurance.
    pool_pre_ping=True,
    # SQLite needs check_same_thread=False via connect_args
    **({} if _is_postgres else {"connect_args": {"check_same_thread": False}}),
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class ScanModel(Base):
    __tablename__ = "scans"

    scan_id         = Column(String(36), primary_key=True)           # UUID string
    name            = Column(String, nullable=True)                   # human-readable label
    target_range    = Column(String, nullable=False)
    scan_type       = Column(String(10), nullable=False)             # quick/deep/stealth
    agent_scan_type = Column(String(10), nullable=False)             # low/medium/high
    agent_mode      = Column(String(20), nullable=False, default="autonomous")
    status          = Column(String(20), nullable=False, default="running")
    run_dir         = Column(String, nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    completed_at    = Column(DateTime(timezone=True), nullable=True)
    duration_s      = Column(Float, nullable=True)
    error_message   = Column(Text, nullable=True)
    devices_count   = Column(Integer, default=0)
    vulns_count     = Column(Integer, default=0)
    avg_cvss        = Column(Float, nullable=True)

    devices         = relationship("DeviceModel", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityModel", back_populates="scan", cascade="all, delete-orphan")
    reports         = relationship("ReportModel", back_populates="scan", cascade="all, delete-orphan")
    events          = relationship("ActivityEventModel", back_populates="scan", cascade="all, delete-orphan")


class DeviceModel(Base):
    __tablename__ = "devices"

    id              = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    scan_id         = Column(String(36), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    ip              = Column(String(45), nullable=False)
    hostname        = Column(String, nullable=True)
    mac_address     = Column(String(20), nullable=True)
    mac_vendor      = Column(String, nullable=True)
    device_type     = Column(String, nullable=True)
    os_name         = Column(String, nullable=True)
    os_accuracy     = Column(Integer, nullable=True)
    description     = Column(Text, nullable=True)
    status          = Column(String(20), default="online")
    severity        = Column(String(20), default="low")
    cvss_score      = Column(Float, default=0.0)
    subnet          = Column(String(50), nullable=True)
    raw_os_json     = Column(Text, nullable=True)       # JSON stored as text (SQLite compat)
    raw_services_json = Column(Text, nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    scan            = relationship("ScanModel", back_populates="devices")


class VulnerabilityModel(Base):
    __tablename__ = "vulnerabilities"

    id                       = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    scan_id                  = Column(String(36), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    device_id                = Column(BigInteger().with_variant(Integer, "sqlite"), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    cve_id                   = Column(String(30), nullable=False)
    affected_device_ip       = Column(String(45), nullable=False)
    affected_device_hostname = Column(String, nullable=True)
    product                  = Column(String, nullable=True)
    version                  = Column(String, nullable=True)
    cvss_score_raw           = Column(Float, nullable=True)
    cvss_score_predicted     = Column(Float, nullable=True)
    severity                 = Column(String(20), nullable=True)
    summary                  = Column(Text, nullable=True)
    exploitable              = Column(Boolean, nullable=True)
    remediation              = Column(Text, nullable=True)
    exploit_availability     = Column(String(20), default="none")
    status                   = Column(String(20), default="queued")
    access_authentication    = Column(String, nullable=True)
    access_complexity        = Column(String, nullable=True)
    access_vector            = Column(String, nullable=True)
    impact_availability      = Column(String, nullable=True)
    impact_confidentiality   = Column(String, nullable=True)
    impact_integrity         = Column(String, nullable=True)
    cwe_code                 = Column(String, nullable=True)
    cwe_name                 = Column(String, nullable=True)
    created_at               = Column(DateTime(timezone=True), server_default=func.now())

    scan                     = relationship("ScanModel", back_populates="vulnerabilities")


class ReportModel(Base):
    __tablename__ = "reports"

    id                = Column(String(36), primary_key=True)
    scan_id           = Column(String(36), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    template_id       = Column(String(50), nullable=False)
    raw_markdown      = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    scope             = Column(Text, nullable=True)
    methodology       = Column(Text, nullable=True)
    key_findings      = Column(Text, nullable=True)
    recommendations   = Column(Text, nullable=True)
    risk_critical     = Column(Integer, default=0)
    risk_high         = Column(Integer, default=0)
    risk_medium       = Column(Integer, default=0)
    risk_low          = Column(Integer, default=0)
    created_at        = Column(DateTime(timezone=True), server_default=func.now())

    scan              = relationship("ScanModel", back_populates="reports")


class ActivityEventModel(Base):
    __tablename__ = "activity_events"

    id          = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    scan_id     = Column(String(36), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=True)
    event_type  = Column(String(20), nullable=False)   # info/warning/critical/patch/exploit
    message     = Column(Text, nullable=False)
    detail      = Column(Text, nullable=True)
    ip          = Column(String(45), nullable=True)
    agent_node  = Column(String(50), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    scan        = relationship("ScanModel", back_populates="events")


class ScanProfileModel(Base):
    __tablename__ = "scan_profiles"

    id          = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    target      = Column(String, nullable=False)
    scan_type   = Column(String(10), nullable=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def init_db() -> None:
    """Create all tables if they don't exist (dev/test convenience)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Migrate pre-existing databases: add the name column if missing.
    #
    # This MUST be its own transaction. On Postgres a failed statement aborts
    # the entire transaction, so when this ALTER hits DuplicateColumnError (the
    # normal case — create_all above already made the column) the `except: pass`
    # swallows the error but leaves the transaction poisoned, and the commit on
    # exiting engine.begin() rolls back create_all along with it. The result was
    # init_db() returning cleanly having created zero tables. SQLite doesn't
    # behave this way, which is why it never showed up in dev.
    async with engine.begin() as conn:
        try:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN name TEXT"))
        except Exception:
            pass  # column already exists


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        yield session
