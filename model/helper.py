"""
@author: Brianna Hinds
Description: Helper functions for the agentic model.
"""
from globals import SANITIZATION_TIER_CONFIG, METACHARACTERS
import re
import json

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

    Args:
        flags: List of flags from nmap command
        tier: user inputed string, either "low", "medium", "high"
    """
    config = SANITIZATION_TIER_CONFIG.get(tier)
    if config is None:
        return {"error": f"unknown tier value: {tier}"}
    
    # check for metacharacters
    combined_tokens = " ".join(flags)
    if any(m in combined_tokens for m in METACHARACTERS):
        return {"error": "~DISALLOWED SHELL/OPERATOR IN FLAGS"}
    
    allowed = config["allowed_flags"]

    for tok in flags:
        if not tok.startswith("-"):
            continue
        if tok.startswith("-T"):
            if not any(t.startswith("-T") for t in allowed):
                return {"error": f"timing template {tok} not allowed for tier {tier}"}
            continue
        if tok in ("-oX", "-oX-"):
            continue
        if tok.startswith("-p"):
            if "-p" not in allowed:
                return {"error": "port scans not allowed for this tier"}
            continue
        if tok not in allowed:
            return {"error": f"flag '{tok}' not allowed for tier {tier}"}

    # validate port ranges
    max_port_range = config["max_port_range"]
    port_exprs = _extract_port_expressions(flags)
    if port_exprs:
        if max_port_range == 0:
            return {"error": "port scans are disabled for this tier"}
        for expr in port_exprs:
            if not _validate_port_expr(expr, max_port_range):
                return {"error": f"port expression '{expr}' exceeds max allowed port {max_port_range}"}

    # ensure -oX - is defined
    if "-oX" not in flags:
        flags.extend(["-oX", "-"])

    return flags


## --- JSON FUNCTIONS -- ##
def extract_json(raw_text: str, iteration: int = 0) -> dict:
    """
    Try to extract a valid JSON object from raw LLM output.
    Uses regex to find JSON blocks and falls back safely.
    """
    # Look for all JSON-like objects in the text
    matches = re.findall(r"\{.*?\}", raw_text, re.DOTALL)

    for m in matches:
        try:
            return json.loads(m)  # first valid JSON wins
        except json.JSONDecodeError as e:
            print(f"~[Iteration {iteration}]. Invalid JSON candidate, skipping: {e}")

    # If nothing valid was found
    print(f"~[Iteration {iteration}]. No valid JSON found in LLM output")
    return {}
