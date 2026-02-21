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

# Conservative port -> (vendor, product) fallback for when nmap service banners
# are absent. These are rough guesses — service banner data from parsed_network
# takes priority and will override these via deduplication.
PORT_TO_PRODUCT = {
    "21":   ("", "ftp"),
    "22":   ("openbsd", "openssh"),
    "53":   ("", "bind"),
    "80":   ("", "apache"),
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
    Parse CPE 2.2 (cpe:/type:vendor:product:version) or
    CPE 2.3 (cpe:2.3:type:vendor:product:version:...) strings.
    Returns None for malformed or unrecognized CPEs.
    """
    if cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(":")[2:]  # strip "cpe" and "2.3"
    elif cpe_str.startswith("cpe:/"):
        parts = cpe_str.replace("cpe:/", "").split(":")
    else:
        return None

    if len(parts) < 3:
        return None

    return {
        "cpe_type": parts[0],
        "vendor":   parts[1] if len(parts) > 1 else "",
        "product":  parts[2] if len(parts) > 2 else "",
        "version":  parts[3] if len(parts) > 3 else "",
        "raw":      cpe_str,
    }


def _extract_product_queries(os_fingerprint: dict, parsed_network: dict | list) -> list[dict]:
    """
    Build a deduplicated list of (host, vendor, product, version, source) CVE
    query tuples from two complementary sources:

    Source A — OS fingerprint CPEs (higher precision, runs first):
        1. Non-generic device/OS CPEs (IoT, Android, Netgear, AXIS, etc.)
        2. Pinned-version Linux kernel CPEs (e.g., 2.6.32.x; rejects major-only)
        3. Open port -> known service product fallback via PORT_TO_PRODUCT
        4. Windows Server special case

    Source B — Nmap service banners from parsed_network (runs second):
        Catches specific software versions that OS fingerprinting misses
        (e.g., Apache/2.4.51, OpenSSH_8.9p1). Skipped if already seen.
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

    # ------------------------------------------------------------------ #
    # Source A: OS fingerprint CPEs + port-based fallback                 #
    # ------------------------------------------------------------------ #
    for ip, data in os_fingerprint.items():
        if not data or not isinstance(data, dict):
            continue

        cpes       = data.get("cpe", [])
        ports_used = data.get("ports_used", [])

        # Pass 1: Categorize CPEs by specificity
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

        for p in non_generic_cpes:
            add_query(ip, p["vendor"], p["product"], p["version"], "cpe_device")

        if specific_kernel_cpes:
            best = max(specific_kernel_cpes, key=lambda x: _cpe_specificity(x["raw"]))
            add_query(ip, best["vendor"], best["product"], best["version"], "cpe_kernel")

        # Pass 2: Open ports -> known service products (low-precision fallback)
        open_ports = [p["portid"] for p in ports_used if p.get("state") == "open"]
        for portid in open_ports:
            if portid in PORT_TO_PRODUCT:
                svc_vendor, svc_product = PORT_TO_PRODUCT[portid]
                add_query(ip, svc_vendor, svc_product, "", f"port_{portid}")

        # Pass 3: Windows Server special case
        os_name = (data.get("os_matches") or [{}])[0].get("name", "").lower()
        if "windows server 2019" in os_name:
            add_query(ip, "microsoft", "windows_server_2019", "2019", "os_windows")

    # ------------------------------------------------------------------ #
    # Source B: Nmap service banners from parsed_network                  #
    # ------------------------------------------------------------------ #
    hosts = parsed_network if isinstance(parsed_network, list) else list(parsed_network.values())
    for host in hosts:
        ip       = host.get("host") or host.get("ip", "unknown")
        services = host.get("services") or host.get("ports") or []
        for svc in services:
            product = svc.get("product") or svc.get("name", "")
            vendor  = svc.get("vendor", "")
            version = svc.get("version", "")
            if product:
                add_query(ip, vendor, product, version, "nmap_banner")

    logger.info(f"Extracted {len(queries)} unique CVE queries (OS CPE + nmap banners)")
    return queries


def vulnerability(state: AgentState) -> AgentState:
    """
    Analyze reconnaissance and OS fingerprint data to identify known vulnerabilities:
      1. Extract (host, vendor, product, version) tuples from OS fingerprint CPEs
         and nmap service banners, with OS CPE data taking priority.
      2. Call cve_search() for each unique (vendor, product) pair with rate limiting.
      3. Pass grounded CVE results to the LLM for structured CVSS scoring.

    Returns:
        AgentState: Updated state containing `vuln_raw_results`.
    """
    logger.info("Vulnerability agent started")

    recon_results  = state.get("recon_results", {})
    os_fingerprint = state.get("os_fingerprint_results", {})

    # Unwrap parsed_network from recon_results safely
    parsed_network = (
        recon_results.get("parsed_network", recon_results)
        if isinstance(recon_results, dict)
        else recon_results
    )

    if not os_fingerprint and not parsed_network:
        logger.warning("No OS fingerprint or recon data available; skipping vulnerability agent.")
        state["vuln_raw_results"] = []
        return state

    # ------------------------------------------------------------------ #
    # Step 1: Extract targeted CVE queries from both data sources         #
    # ------------------------------------------------------------------ #
    queries = _extract_product_queries(os_fingerprint, parsed_network)

    if not queries:
        logger.warning("No CVE queries extracted; skipping CVE fetch.")
        state["vuln_raw_results"] = []
        return state

    # ------------------------------------------------------------------ #
    # Step 2: Fetch real CVEs from CIRCL for each unique product          #
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    # Step 3: LLM normalization and CVSS scoring                          #
    # ------------------------------------------------------------------ #

    # Compact OS summary — avoids dumping the raw fingerprint blob
    os_summary = {
        ip: {
            "best_os_match": (d.get("os_matches") or [{}])[0].get("name", "unknown"),
            "accuracy":      d.get("accuracy", 0),
            "open_ports":    [p["portid"] for p in d.get("ports_used", []) if p.get("state") == "open"],
            "cpe":           d.get("cpe", []),
        }
        for ip, d in os_fingerprint.items() if d
    }

    # Compact service banner summary from parsed_network
    hosts = parsed_network if isinstance(parsed_network, list) else list(parsed_network.values())
    service_summary = {}
    for host in hosts:
        ip       = host.get("host") or host.get("ip", "unknown")
        services = host.get("services") or host.get("ports") or []
        banner_entries = [
            {k: svc.get(k, "") for k in ("product", "vendor", "version")}
            for svc in services if svc.get("product") or svc.get("name")
        ]
        if banner_entries:
            service_summary[ip] = banner_entries

    vuln_llm_prompt = f"""
    You are a vulnerability analyst. You have been given real CVE data fetched live from CIRCL
    for the network hosts below. Your job is to produce a clean, structured JSON array.

    --- OS Fingerprint Summary (per host) ---
    {json.dumps(os_summary, indent=2)}

    --- Nmap Service Banners (per host) ---
    {json.dumps(service_summary, indent=2)}

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
    - Use service banner data to confirm or refine version information where possible.
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
