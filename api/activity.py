"""
Synchronous activity event writer — safe to call from agent threads.

Agents run in synchronous functions (inside asyncio.to_thread), so they
can't await the async DB session.  This module uses:
  1. A ContextVar to carry the current scan_id from the async background
     task into any threads it spawns (asyncio.to_thread propagates context).
  2. A small sync SQLAlchemy engine purely for writing activity_events rows.
"""

from __future__ import annotations

import os
from contextvars import ContextVar
from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# ContextVar — set once per scan in _run_scan_background, auto-propagated
# into threads via asyncio.to_thread's context copy.
_current_scan_id: ContextVar[str | None] = ContextVar("current_scan_id", default=None)


def set_scan_context(scan_id: str) -> None:
    """Call this in the async background task before graph.astream()."""
    _current_scan_id.set(scan_id)


# Sync engine — derive URL from the async DATABASE_URL env var
_async_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./surge.db")
_sync_url = (
    _async_url
    .replace("sqlite+aiosqlite", "sqlite")
    .replace("postgresql+asyncpg", "postgresql+psycopg2")
)

_engine = create_engine(
    _sync_url,
    pool_pre_ping=True,   # remote Postgres — see api/db.py
    **({} if "postgresql" in _sync_url else {"connect_args": {"check_same_thread": False}}),
)
_Session = sessionmaker(bind=_engine)


def emit_activity_sync(
    message: str,
    event_type: str = "info",
    agent_node: str | None = None,
    ip: str | None = None,
    detail: str | None = None,
) -> None:
    """Write a single activity_events row synchronously.  Never raises."""
    scan_id = _current_scan_id.get()
    if not scan_id:
        return
    try:
        with _Session() as session:
            session.execute(
                text(
                    "INSERT INTO activity_events "
                    "(scan_id, event_type, message, agent_node, ip, detail, created_at) "
                    "VALUES (:scan_id, :event_type, :message, :agent_node, :ip, :detail, :created_at)"
                ),
                {
                    "scan_id":    scan_id,
                    "event_type": event_type,
                    "message":    message,
                    "agent_node": agent_node,
                    "ip":         ip,
                    "detail":     detail,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            session.commit()
    except Exception:
        pass  # never let a logging failure crash an agent
