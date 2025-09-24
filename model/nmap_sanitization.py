"""
@author: Brianna Hinds
Description: Method definitions of nmap command sanitization
"""
import re

## --- CONFIGURATIONS --- ##
TIER_CONFIG = {
    "low": {  # only host discovery
        "allowed_flags": {"-sn", "-T0", "-T1", "-T2", "-T3", "-T4"},
        "max_port_range": 0,   # 0 indicates "no port scans allowed"
        "max_runtime_s": 120,
        "allow_service_detection": False,
    },
    "medium": {  # limited port/sreeevice scans
        "allowed_flags": {"-sn", "-sS", "-sT", "-sV", "-Pn", "-T0", "-T1", "-T2", "-T3"},
        "max_port_range": 1024,  # allow ports up to 1-1024 (or lists of ports within that)
        "max_runtime_s": 300,
        "allow_service_detection": True,
    },
    "high": {  # "critical" / admin-approved — wide permissions
        "allowed_flags": {
            "-sn", "-sS", "-sT", "-sU", "-sV", "-O", "-Pn",
            "-T0", "-T1", "-T2", "-T3", "-T4", "-p"  # -p treated specially
        },
        "max_port_range": 65535,
        "max_runtime_s": 1800,
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")

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
    config = TIER_CONFIG.get(tier)
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
