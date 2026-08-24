from core.state import AgentState
from core.llm import get_llm
from execution.json_extract import extract_json
from agents.prompts import VULN_AGENT_SYSTEM_PROMPT
from agents.dashboard_payload import dashboard_data_grab
from execution.cve_search import cve_search
from config.logging_config import get_logger
from api.activity import emit_activity_sync

from langchain.schema import SystemMessage, HumanMessage
import json
import re
import time

logger = get_logger(__name__)


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
    query tuples from three complementary sources:

    Source A — OS fingerprint CPEs (higher precision, runs first):
        1. Non-generic device/OS CPEs (IoT, Android, Netgear, AXIS, etc.)
        2. Pinned-version Linux kernel CPEs (e.g., 4.4.x; accepts major.minor+)
        3. Windows Server special case

    Source B — Service-level CPEs from parsed_network (runs second):
        Application CPEs (type 'a') from nmap service detection. Most precise
        source for software CVEs (e.g., cpe:/a:mysql:mysql:5.7.33).

    Source C — Nmap service banners from parsed_network (runs last):
        Catches product/version strings not covered by CPEs. Falls back to
        the nmap service name (e.g., "mysql", "ssh") when product is absent.
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

    hosts_list = parsed_network if isinstance(parsed_network, list) else list(parsed_network.values())

    # Ordered most-specific first so the first match wins per host.
    _OS_NAME_MAP = [
        ("windows server 2022", "microsoft",    "windows_server_2022", "2022"),
        ("windows server 2019", "microsoft",    "windows_server_2019", "2019"),
        ("windows server 2016", "microsoft",    "windows_server_2016", "2016"),
        ("windows server 2012", "microsoft",    "windows_server_2012", "2012"),
        ("windows server 2008", "microsoft",    "windows_server_2008", "2008"),
        ("windows 11",          "microsoft",    "windows_11",          "11"),
        ("windows 10",          "microsoft",    "windows_10",          "10"),
        ("windows 8.1",         "microsoft",    "windows_8.1",         "8.1"),
        ("windows 8",           "microsoft",    "windows_8",           "8"),
        ("windows 7",           "microsoft",    "windows_7",           "7"),
        ("mac os x",            "apple",        "mac_os_x",            ""),
        ("macos",               "apple",        "mac_os_x",            ""),
        ("iphone",              "apple",        "iphone_os",           ""),
        ("android",             "google",       "android",             ""),
        ("ubuntu",              "canonical",    "ubuntu_linux",        ""),
        ("debian",              "debian",       "debian_linux",        ""),
        ("centos",              "centos",       "centos",              ""),
        ("red hat",             "redhat",       "enterprise_linux",    ""),
        ("fedora",              "fedoraproject","fedora",              ""),
    ]

    # ------------------------------------------------------------------ #
    # Source A: OS fingerprint CPEs                                       #
    # ------------------------------------------------------------------ #
    for ip, data in os_fingerprint.items():
        if not data or not isinstance(data, dict):
            continue

        cpes = data.get("cpe", [])

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

            if ctype == "h":
                non_generic_cpes.append(parsed)
            elif ctype == "o" and vendor not in ("linux", ""):
                non_generic_cpes.append(parsed)
            # Accept major.minor (e.g., 4.4) and above — previously required X.Y.Z
            elif product == "linux_kernel" and version and re.match(r"^\d+\.\d+", version):
                specific_kernel_cpes.append(parsed)

        for p in non_generic_cpes:
            add_query(ip, p["vendor"], p["product"], p["version"], "cpe_device")

        if specific_kernel_cpes:
            best = max(specific_kernel_cpes, key=lambda x: _cpe_specificity(x["raw"]))
            add_query(ip, best["vendor"], best["product"], best["version"], "cpe_kernel")

        # Fallback: if nmap named the OS but produced no usable CPE string,
        # derive a CIRCL query from the human-readable match name.
        os_name = (data.get("os_matches") or [{}])[0].get("name", "").lower()
        for fragment, os_vendor, os_product, os_version in _OS_NAME_MAP:
            if fragment in os_name:
                add_query(ip, os_vendor, os_product, os_version, "os_name")
                break

    # ------------------------------------------------------------------ #
    # Source B: Service-level CPEs from parsed_network (application CPEs) #
    # ------------------------------------------------------------------ #
    for host in hosts_list:
        ip       = host.get("ip", "unknown")
        services = host.get("services") or []
        for svc in services:
            if svc.get("state") != "open":
                continue
            for cpe_str in svc.get("cpe", []):
                parsed = _parse_cpe(cpe_str)
                if not parsed or parsed["cpe_type"] != "a" or not parsed["product"]:
                    continue
                add_query(ip, parsed["vendor"], parsed["product"], parsed["version"], "svc_cpe")

    # ------------------------------------------------------------------ #
    # Source C: Nmap service banners (product strings + service names)    #
    # ------------------------------------------------------------------ #
    # Generic protocol/service names that map to many unrelated vendors in CIRCL.
    # Only applies when falling back to the raw service name — an explicit nmap
    # product string (e.g. "OpenSSH", "Apache httpd") is always queried.
    _GENERIC_SERVICE_BLOCKLIST = frozenset({
        "http", "https", "ssh", "ftp", "smtp", "snmp", "telnet", "dns",
        "smb", "netbios", "msrpc", "nfs", "ldap", "rdp", "vnc",
        "tcpwrapped", "unknown", "ssl", "tls",
    })

    for host in hosts_list:
        ip              = host.get("ip", "unknown")
        services        = host.get("services") or []
        for svc in services:
            if svc.get("state") != "open":
                continue
            vendor          = (svc.get("vendor") or "").strip()
            version         = (svc.get("version") or "").strip()
            detected_product = (svc.get("product") or "").strip()
            service_name    = (svc.get("service") or "").strip()

            if detected_product and detected_product.lower() not in ("unknown", "tcpwrapped"):
                # Nmap explicitly identified the software — query it unconditionally.
                # The blocklist doesn't apply here; if nmap says "OpenSSH" we trust it.
                add_query(ip, vendor, detected_product, version, "nmap_banner")
            elif service_name and service_name.lower() not in _GENERIC_SERVICE_BLOCKLIST:
                # No specific product detected — only use the service name when it's
                # something specific enough (e.g. "mysql", "postgresql", not "http").
                add_query(ip, vendor, service_name, version, "nmap_banner")

    logger.info(f"Extracted {len(queries)} unique CVE queries (OS CPE + svc CPE + nmap banners)")
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
    emit_activity_sync("Scanning for vulnerabilities — querying CVE database", event_type="warning", agent_node="vulnerability")

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
        return {"vuln_raw_results": []}

    # ------------------------------------------------------------------ #
    # Step 1: Extract targeted CVE queries from both data sources         #
    # ------------------------------------------------------------------ #
    queries = _extract_product_queries(os_fingerprint, parsed_network)

    if not queries:
        logger.warning("No CVE queries extracted; skipping CVE fetch.")
        return {"vuln_raw_results": []}

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

    llm = get_llm(tier="analysis")
    vuln_result = llm.invoke([
        SystemMessage(content=VULN_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=vuln_llm_prompt),
    ])

    raw    = vuln_result.content
    parsed = extract_json(raw)

    if not isinstance(parsed, list):
        logger.warning("Vulnerability agent returned invalid JSON; defaulting to []")
        parsed = []

    # Write an intermediate dashboard snapshot — devices with raw CVE/CVSS data
    # attached, before the ML scoring model runs. The frontend live view will show
    # vulns appearing on devices while CVSS scoring is still in progress.
    try:
        recon = state.get("recon_results", {})
        parsed_network = (
            recon.get("parsed_network", recon) if isinstance(recon, dict) else recon
        )
        # Map raw cvss_score → predicted_score so dashboard_data_grab can render severity
        interim_vulns = [
            {**v, "predicted_score": v.get("cvss_score") or 0.0}
            for v in parsed
        ]
        snapshot = dashboard_data_grab(
            interim_vulns,
            discovered_hosts=recon.get("discovered_hosts", []),
            parsed_network=parsed_network,
        )
        run_dir = state.get("run_dir", "")
        with open(f"{run_dir}/dashboard_data.json", "w") as f:
            json.dump(snapshot, f, indent=4)
        logger.info("Intermediate dashboard snapshot written after vulnerability scan.")
    except Exception as e:
        logger.warning(f"Failed to write intermediate dashboard snapshot: {e}")

    emit_activity_sync(
        f"Vulnerability scan complete — {len(parsed)} CVE{'s' if len(parsed) != 1 else ''} found",
        event_type="success",
        agent_node="vulnerability",
    )
    logger.info(f"Vulnerability agent complete — {len(parsed)} CVE entries stored.")

    return {"vuln_raw_results": parsed}
