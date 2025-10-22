"""
@author: Brianna Hinds
Description: Helper functions for the agentic model.
"""
from globals import SANITIZATION_TIER_CONFIG, METACHARACTERS
import re
import json
import datetime

## --- SANITIZATION METHODS --- ##
def _extract_port_expressions(flags: list[str]) -> list[str]:
    """
    Extracts any port expressions from the provided flag tokens.
    Examples: "-p22", "-p1-1024", "-p22,80,443" or ["-p", "22,80,443"].
    """
    port_exprs = []
    i = 0
    while i < len(flags):
        tok = flags[i]
        if tok == "-p" and i + 1 < len(flags):
            port_exprs.append(flags[i+1])
            i += 2
            continue
        if tok.startswith("-p") and len(tok) > 2:
            port_exprs.append(tok[2:])
        i += 1
    return port_exprs


def _validate_port_expr(expr: str, max_port: int) -> bool:
    """
    Returns True if all ports in the expression are within range.
    Supports single, ranges, and comma-separated lists.
    """
    for part in expr.split(","):
        if "-" in part:
            try:
                low, high = part.split("-", 1)
                low, high = int(low), int(high)
            except ValueError:
                return False
            if low < 0 or high < 0 or high > max_port:
                return False
        else:
            try:
                port = int(part)
            except ValueError:
                return False
            if port < 0 or port > max_port:
                return False
    return True


def sanitize_flags_for_tier(flags: list[str], tier: str):
    """
    Validate and sanitize tokenized flag list based on the tier requested.
    Returns a sanitized list of tokens OR {"error": "MESSAGE"}
    """
    config = SANITIZATION_TIER_CONFIG.get(tier)
    if config is None:
        return {"error": f"unknown tier value: {tier}"}

    # check for metacharacters
    combined_tokens = " ".join(flags)
    if any(m in combined_tokens for m in METACHARACTERS):
        return {"error": "~DISALLOWED SHELL/OPERATOR IN FLAGS"}

    allowed = config["allowed_flags"]
    max_port_range = config["max_port_range"]

    sanitized_flags = []
    i = 0
    while i < len(flags):
        tok = flags[i]

        # keep positional tokens only if they are script args handled below,
        # otherwise positional tokens are suspicious (likely user error)
        if not tok.startswith("-"):
            # treat bare tokens as possible script names only if previous token was --script (handled below)
            # otherwise, keep them — they might be legitimate (some flags accept bare args)
            sanitized_flags.append(tok)
            i += 1
            continue

        # Timing flags like -T4
        if tok.startswith("-T") and any(t.startswith("-T") for t in allowed):
            sanitized_flags.append(tok)
            i += 1
            continue

        # Output flags: accept -oX and -oN and allow a following "-" or file path
        if tok in ("-oX", "-oN", "-oG", "-oA"):
            sanitized_flags.append(tok)
            # include next token if it exists and is not another flag (e.g., '-' or filename)
            if i + 1 < len(flags) and not flags[i+1].startswith("-"):
                sanitized_flags.append(flags[i+1])
                i += 2
            else:
                i += 1
            continue

        # -p forms
        if tok == "-p":
            # keep the -p only if allowed and next token is a port expr within range
            if "-p" in allowed and i + 1 < len(flags) and _validate_port_expr(flags[i+1], max_port_range):
                sanitized_flags.append("-p")
                sanitized_flags.append(flags[i+1])
            # skip the port and its arg otherwise
            i += 2
            continue
        if tok.startswith("-p") and "-p" in allowed:
            expr = tok[2:]
            if _validate_port_expr(expr, max_port_range):
                sanitized_flags.append(tok)
            i += 1
            continue
        if tok.startswith("-p") and "-p" not in allowed:
            # discard any -p forms when not allowed
            i += 1
            continue

        # --script handling (support both "--script name" and "--script=name")
        if tok.startswith("--script"):
            if "--script" not in allowed:
                # script usage not allowed for this tier
                i += 1
                continue

            # case: --script=name
            if "=" in tok:
                sanitized_flags.append(tok)
                i += 1
                continue

            # case: --script <name>
            if i + 1 < len(flags) and not flags[i+1].startswith("-"):
                sanitized_flags.append(tok)
                sanitized_flags.append(flags[i+1])
                i += 2
                continue
            else:
                # standalone --script with no argument: drop it
                i += 1
                continue

        # generic allowed-flag check (applies to all tiers)
        if tok in allowed:
            sanitized_flags.append(tok)
            i += 1
            continue

        # allow flags that start with allowed prefixes (e.g., --version-*)
        if any(tok.startswith(pref) for pref in allowed if pref.endswith("-") or pref.endswith("_")):
            sanitized_flags.append(tok)
            i += 1
            continue

        # if we reach here, token is not allowed — drop it
        i += 1

    # After token loop: normalize port expressions if you prefer unified format
    # (your earlier code replaced -p tokens with exprs; here we keep "-p" and its arg)

    # ensure XML output is requested; if not, add "-oX -"
    has_oX = any(x == "-oX" or x.startswith("-oX") for x in sanitized_flags)
    if not has_oX:
        sanitized_flags.extend(["-oX", "-"])

    return sanitized_flags


## --- JSON FUNCTIONS -- ##
def extract_json(raw_text: str, iteration: int) -> dict:
    """
    Tries to extract JSON from the model output.
    If invalid or missing, logs the issue and returns an empty dict.
    """
    # Try to find JSON block
    match = re.search(r"\{[\s\S]*\}", raw_text)
    if not match:
        print(f"[{datetime.datetime.now()}] WARNING: No JSON block found in iteration {iteration}")
        return {}

    try:
        parsed = json.loads(match.group(0))
        print(f"[{datetime.datetime.now()}] ✅ Extracted valid JSON decision.")
        return parsed
    except json.JSONDecodeError as e:
        print(f"[{datetime.datetime.now()}] ⚠️ Invalid JSON at iteration {iteration}: {e}")
        return {}


## --- RECON AID METHOD -- ##
def summarize_recon_results(recon_results: dict) -> dict:
    """Return counts for LLM prompt from raw recon results."""
    open_ports = 0
    service_count = 0
    os_fingerprint_count = 0
    discovered_hosts = set()

    for host, data in recon_results.items():
        discovered_hosts.add(host)
        ports = data.get("ports", [])
        open_ports += sum(1 for p in ports if p.get("state") == "open")
        service_count += sum(1 for p in ports if p.get("service_version"))
        if data.get("os"):
            os_fingerprint_count += 1

    return {
        "open_ports_count": open_ports,
        "service_count": service_count,
        "os_fingerprint_count": os_fingerprint_count,
    }
