"""
Surge FastAPI application.

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Environment variables (see .env):
    DATABASE_URL          — PostgreSQL or SQLite connection string
    CORS_ORIGINS          — comma-separated allowed origins (default: allow all in dev)
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from api.db import init_db, AsyncSessionLocal, ScanModel
from api.routes import scans, devices, vulns, dashboard, reports, settings
from config.logging_config import setup_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Surge API starting — initialising database")
    await init_db()

    # Mark any scans that were still "running" when the server last shut down.
    # These are orphaned — their background tasks are gone and they'll never
    # complete on their own.
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScanModel).where(ScanModel.status == "running")
        )
        stale = result.scalars().all()
        if stale:
            now = datetime.now(timezone.utc)
            for scan in stale:
                scan.status = "failed"
                scan.error_message = "Interrupted — server restarted"
                scan.completed_at = now
            await session.commit()
            logger.info("Marked %d stale scan(s) as failed on startup", len(stale))

    logger.info("Database ready")
    yield
    logger.info("Surge API shutting down")


app = FastAPI(
    title="Surge API",
    description="REST + WebSocket API bridging the Surge AI agent and the dashboard.",
    version="0.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# If CORS_ORIGINS is set explicitly, use it. Otherwise allow all origins
# so localhost:3000, 127.0.0.1:3000, and any other local dev port all work
# without configuration. Lock this down via CORS_ORIGINS in production.
_raw_origins = os.getenv("CORS_ORIGINS", "")
origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=bool(origins),   # credentials + wildcard is not allowed by spec
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(scans.router)
app.include_router(devices.router)
app.include_router(vulns.router)
app.include_router(dashboard.router)
app.include_router(reports.router)
app.include_router(settings.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok"}
