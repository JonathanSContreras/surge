from core.state import AgentState
from core.llm import get_llm
from execution.json_extract import extract_json
from agents.prompts import VULN_AGENT_SYSTEM_PROMPT
from execution.cve_search import cve_search
from config.logging_config import get_logger

from langchain.schema import SystemMessage, HumanMessage
import json
import re
import time

logger = get_logger(__name__)

# Map open port numbers to (vendor, product) pairs for service-level CVE queries
PORT_TO_PRODUCT = {
    "21":   ("", "ftp"),
    "22":   ("openbsd", "openssh"),
    "53":   ("", "bind"),
    "80":   ("", "apache"),        # rough guess; refine if banner grabbing is added
    "111":  ("", "rpcbind"),
    "443":  ("", "openssl"),
    "445":  ("microsoft", "smb"),
    "3306": ("mysql", "mysql"),
    "5432": ("postgresql", "postgresql"),
}


def _cpe_specificity(cpe: str) -> int:
    """Higher score = more specific (more version info in the CPE string)."""
    parts = cpe.split(":")
    return sum(1 for p in parts[4:] if p and p not in ("*", "-"))


def _parse_cpe(cpe_str: str) -> dict | None:
    """
    Parse a CPE 2.2 URI into vendor/product/version components.
    Format: cpe:/type:vendor:product:version
    Returns None for malformed CPEs.
    """
    parts = cpe_str.replace("cpe:/", "").split(":")
    if len(parts) < 3:
        return None

    return {
        "cpe_type": parts[0],
        "vendor":   parts[1] if len(parts) > 1 else "",
        "product":  parts[2] if len(parts) > 2 else "",
        "version":  parts[3] if len(parts) > 3 else "",
        "raw":      cpe_str,
    }


def _extract_product_queries(os_fingerprint: dict) -> list[dict]:
    """
    Extract CVE-queryable (host, vendor, product, version) tuples from
    os_fingerprint_results, which is keyed by IP address.

    Priority order:
      1. Non-generic device CPEs (Netgear, AXIS, Hikvision, Android, etc.) — best signal
      2. Specific versioned Linux kernel CPEs (e.g., 2.6.32, not just "3")
      3. Open port -> known service product mappings
      4. Windows Server special case
    """
    queries   = []
    seen_keys = set()

    def add_query(host, vendor, product, version, source):
        key = (vendor.lower(), product.lower())
        if key in seen_keys:
            return
        seen_keys.add(key)
        queries.append({
            "host":    host,
            "vendor":  vendor,
            "product": product,
            "version": version,
            "source":  source,
        })

    for ip, data in os_fingerprint.items():
        if not data or not isinstance(data, dict):
            continue

        cpes       = data.get("cpe", [])
        ports_used = data.get("ports_used", [])

        # --- Pass 1: Categorize CPEs ---
        non_generic_cpes     = []
        specific_kernel_cpes = []

        for cpe_str in cpes:
            parsed = _parse_cpe(cpe_str)
            if not parsed or not parsed["product"]:
                continue

            vendor  = parsed["vendor"]
            product = parsed["product"]
            version = parsed["version"]
            ctype   = parsed["cpe_type"]

            # Hardware CPEs for known IoT/device vendors
            if ctype == "h":
                non_generic_cpes.append(parsed)

            # Non-Linux OS with a real product name (e.g., netgear:raidiator, google:android)
            elif ctype == "o" and vendor not in ("linux", ""):
                non_generic_cpes.append(parsed)

            # Linux kernel: only if version is pinned (e.g., 2.6.32), not just major (e.g., "3")
            elif product == "linux_kernel" and version and re.match(r"^\d+\.\d+\.\d+", version):
                specific_kernel_cpes.append(parsed)

        # Add all non-generic device/OS CPEs (these are your best leads)
        for p in non_generic_cpes:
            add_query(ip, p["vendor"], p["product"], p["version"], "cpe_device")

        # Add only the single most specific kernel CPE per host
        if specific_kernel_cpes:
            best = max(specific_kernel_cpes, key=lambda x: _cpe_specificity(x["raw"]))
            add_query(ip, best["vendor"], best["product"], best["version"], "cpe_kernel")

        # --- Pass 2: Open ports -> service products ---
        open_ports = [p["portid"] for p in ports_used if p.get("state") == "open"]
        for portid in open_ports:
            if portid in PORT_TO_PRODUCT:
                svc_vendor, svc_product = PORT_TO_PRODUCT[portid]
                add_query(ip, svc_vendor, svc_product, "", f"port_{portid}")

        # --- Pass 3: Windows Server special case ---
        os_name = (data.get("os_matches") or [{}])[0].get("name", "").lower()
        if "windows server 2019" in os_name:
            add_query(ip, "microsoft", "windows_server_2019", "2019", "os_windows")

    logger.info(f"Extracted {len(queries)} unique CVE queries from OS fingerprint data")
    return queries


def vulnerability(state: AgentState) -> AgentState:
    """
    Analyze OS fingerprint data and identify known vulnerabilities by:
      1. Parsing os_fingerprint_results CPEs and open ports into targeted queries.
      2. Calling cve_search() for each unique (vendor, product) to get real CVE data.
      3. Passing the grounded CVE results to the LLM for structured CVSS scoring.

    Returns:
        AgentState: Updated state containing `vuln_raw_results`.
    """
    logger.info("Vulnerability agent started")

    os_fingerprint = state.get("os_fingerprint_results", {})

    # ------------------------------------------------------------------
    # Step 1: Extract targeted CVE queries from OS fingerprint CPEs
    # ------------------------------------------------------------------
    queries = _extract_product_queries(os_fingerprint)

    # ------------------------------------------------------------------
    # Step 2: Fetch real CVEs from CIRCL for each unique product
    # ------------------------------------------------------------------
    cve_db = []

    for q in queries:
        try:
            results = cve_search.func(product=q["product"], vendor=q["vendor"])
            if isinstance(results, list) and results:
                cve_db.append({
                    "host":    q["host"],
                    "product": q["product"],
                    "vendor":  q["vendor"],
                    "version": q["version"],
                    "source":  q["source"],
                    "cves":    results,
                })
                logger.info(f"  [{q['source']}] {q['vendor']}/{q['product']}: {len(results)} CVEs")
            else:
                logger.info(f"  [{q['source']}] {q['vendor']}/{q['product']}: no results")
        except Exception as e:
            logger.warning(f"  cve_search failed for {q['product']}: {e}")
        finally:
            time.sleep(0.5)

    logger.info(f"CVE fetch complete — {len(cve_db)} products with results")

    # ------------------------------------------------------------------
    # Step 3: LLM normalization, deduplication, and CVSS scoring
    # ------------------------------------------------------------------

    # Compact OS summary for the prompt (avoid dumping the entire raw fingerprint)
    os_summary = {
        ip: {
            "best_os_match": (d.get("os_matches") or [{}])[0].get("name", "unknown"),
            "accuracy":      d.get("accuracy", 0),
            "open_ports":    [p["portid"] for p in d.get("ports_used", []) if p.get("state") == "open"],
            "cpe":           d.get("cpe", []),
        }
        for ip, d in os_fingerprint.items() if d
    }

    vuln_llm_prompt = f"""
    You are a vulnerability analyst. You have been given real CVE data fetched live from CIRCL
    for the network hosts below. Your job is to produce a clean, structured JSON array.

    --- OS Fingerprint Summary (per host) ---
    {json.dumps(os_summary, indent=2)}

    --- Live CVE Data (from CIRCL) ---
    {json.dumps(cve_db, indent=2)}

    Instructions:
    For each CVE in the live data above, output ONE JSON object with these fields:
    "host"        : IP address of the affected host
    "product"     : product/service name
    "version"     : version string (empty string if unknown)
    "cve_id"      : CVE identifier (e.g. "CVE-2021-44228")
    "cvss_score"  : numeric CVSS score (0.0-10.0), or null if unknown
    "severity"    : "Critical" (9-10) | "High" (7-8.9) | "Medium" (4-6.9) | "Low" (0.1-3.9) | "Unknown"
    "summary"     : one-sentence plain-English description of the vulnerability
    "exploitable" : true | false — your assessment based on the CVE description
    "remediation" : one-sentence fix recommendation

    Rules:
    - ONLY include CVEs present in the live CVE data above. Never invent or hallucinate CVE IDs.
    - If a CVE applies to multiple hosts (same product/version), output one entry per affected host.
    - Sort output by cvss_score descending (Critical first).
    - If the live data is empty, return [].
    - Output a raw JSON array ONLY. No markdown. No explanation. No preamble.
    """

    llm = get_llm()
    vuln_result = llm.invoke([
        SystemMessage(content=VULN_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=vuln_llm_prompt),
    ])

    raw    = vuln_result.content
    parsed = extract_json(raw)

    if not isinstance(parsed, list):
        logger.warning("Vulnerability agent returned invalid JSON; defaulting to []")
        parsed = []

    state["vuln_raw_results"] = parsed
    logger.info(f"Vulnerability agent complete — {len(parsed)} CVE entries stored.")

    return state