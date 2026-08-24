from config.constants import SANITIZATION_TIER_CONFIG, METACHARACTERS

## --- SANITIZATION METHODS --- ##
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

        # timing flags like -T4
        if tok.startswith("-T") and any(t.startswith("-T") for t in allowed):
            sanitized_flags.append(tok)
            i += 1
            continue

        # output flags: accept -oX and -oN and allow a following "-" or file path
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
                # standalone --script with no argument
                i += 1
                continue

        # generic allowed-flag check (applies to all tiers)
        if tok in allowed:
            sanitized_flags.append(tok)
            i += 1
            continue

        # allow flags that start with allowed prefixes
        if any(tok.startswith(pref) for pref in allowed if pref.endswith("-") or pref.endswith("_")):
            sanitized_flags.append(tok)
            i += 1
            continue

        # if we reach here, token is not allowed
        i += 1

    # ensure XML output is requested, if not, add "-oX -"
    has_oX = any(x == "-oX" or x.startswith("-oX") for x in sanitized_flags)
    if not has_oX:
        sanitized_flags.extend(["-oX", "-"])

    return sanitized_flags