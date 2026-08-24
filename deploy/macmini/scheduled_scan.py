#!/usr/bin/env python3
"""
Scheduled Surge scan — invoked by com.surge.schedule.plist at 09:00 and 15:00, Mon-Fri.

Does three things before it will start a scan:

  1. OVERLAP GUARD. Refuses to start if a scan is already running. The two slots
     are six hours apart but a Deep scan can run 3-5h (RECON_CONVERGENCE
     .time_budget_seconds is 7200, TIMEOUT_VAL is 3600 per nmap call), so the
     09:00 run can still be going at 15:00. Two concurrent runs would put two
     nmap floods on the same network and confuse the live-mode active_scans
     logic. This is also why the default scan type here is 'quick', not 'deep'.

  2. CREDIT CHECK. If the OpenRouter balance drops below CREDIT_FLOOR, flips the
     API to offline mode so scans degrade to the local model instead of failing
     outright. Flips back to online when there's headroom again.

  3. Only then POSTs the scan.

Exit codes: 0 = scan started or deliberately skipped, 1 = something was wrong.
Everything is logged to stdout, which launchd captures to /var/log/surge-schedule.log.
"""

import datetime
import os
import sys

import requests

API         = os.getenv("SURGE_API",    "http://127.0.0.1:8000")
TARGET      = os.getenv("SURGE_TARGET", "")          # blank => backend auto-detects via ARP/gateway
SCAN_TYPE   = os.getenv("SURGE_SCAN_TYPE", "quick")  # quick|normal|deep|stealth
CREDIT_FLOOR = float(os.getenv("SURGE_CREDIT_FLOOR", "2.00"))
TIMEOUT     = 30


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)


def running_scans() -> list:
    r = requests.get(f"{API}/scans", timeout=TIMEOUT)
    r.raise_for_status()
    return [s for s in r.json() if s.get("status") == "running"]


def credits_remaining() -> float | None:
    """Dollars left on the OpenRouter key, or None if it can't be determined."""
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        return None
    try:
        r = requests.get("https://openrouter.ai/api/v1/auth/key",
                         headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json().get("data", {})
        return (d.get("limit") or 50.0) - d.get("usage", 0)
    except Exception as exc:
        log(f"WARN  could not read credit balance: {exc}")
        return None


def set_mode(mode: str) -> None:
    r = requests.put(f"{API}/settings/model", json={"mode": mode}, timeout=TIMEOUT)
    r.raise_for_status()
    log(f"      model mode set to '{mode}'")


def main() -> int:
    slot = "09:00" if datetime.datetime.now().hour < 12 else "15:00"
    log(f"scheduled run ({slot} slot) starting")

    try:
        requests.get(f"{API}/health", timeout=TIMEOUT).raise_for_status()
    except Exception as exc:
        log(f"ABORT api unreachable at {API}: {exc}")
        return 1

    # 1. overlap guard
    try:
        active = running_scans()
    except Exception as exc:
        log(f"ABORT could not list scans: {exc}")
        return 1
    if active:
        names = ", ".join(s.get("name") or s["scan_id"][:8] for s in active)
        log(f"SKIP  a scan is already running ({names}) — not starting a second one")
        return 0

    # 2. credit check
    remaining = credits_remaining()
    if remaining is not None:
        log(f"      OpenRouter balance: ${remaining:.2f}")
        try:
            set_mode("offline" if remaining < CREDIT_FLOOR else "online")
            if remaining < CREDIT_FLOOR:
                log(f"      below floor of ${CREDIT_FLOOR:.2f} — falling back to the local model")
        except Exception as exc:
            log(f"WARN  could not set model mode: {exc}")

    # 3. start the scan
    body = {
        "name":       f"Scheduled — {datetime.date.today().isoformat()} {slot}",
        "scan_type":  SCAN_TYPE,
        "agent_mode": "autonomous",
    }
    if TARGET:
        body["target"] = TARGET
    try:
        r = requests.post(f"{API}/scans", json=body, timeout=TIMEOUT)
        r.raise_for_status()
    except Exception as exc:
        log(f"ABORT scan creation failed: {exc}")
        return 1

    log(f"OK    started {SCAN_TYPE} scan: {r.json()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
