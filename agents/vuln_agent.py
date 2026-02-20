from core.state import AgentState
from core.llm import get_llm
from execution.json_extract import extract_json
from agents.prompts import VULN_AGENT_SYSTEM_PROMPT
from config.logging_config import get_logger
from execution.cve_search import cve_search  # <-- import the tool directly

import json
from langchain.schema import SystemMessage, HumanMessage

logger = get_logger(__name__)


def _extract_product_queries(recon_results: dict | list) -> list[dict]:
    """
    Parse recon_results and return a flat list of
    {"host": ..., "product": ..., "vendor": ..., "version": ...} dicts
    to use as CVE search queries.

    Adjust the field names below to match your actual recon_results schema.
    """
    queries = []

    # recon_results may be a list of host dicts or a dict keyed by host IP
    hosts = recon_results if isinstance(recon_results, list) else list(recon_results.values())

    for host in hosts:
        ip = host.get("host") or host.get("ip", "unknown")
        services = host.get("services") or host.get("ports") or []
        for svc in services:
            product = svc.get("product") or svc.get("name", "")
            vendor  = svc.get("vendor", "")
            version = svc.get("version", "")
            if product:
                queries.append({
                    "host": ip,
                    "product": product,
                    "vendor": vendor,
                    "version": version,
                })

    # Fallback: if no services were parsed, try to query based on OS fingerprint
    if not queries:
        for host in hosts:
            ip  = host.get("host") or host.get("ip", "unknown")
            os_ = host.get("os") or host.get("os_match", "")
            if "linux" in os_.lower():
                queries.append({"host": ip, "product": "linux_kernel", "vendor": "linux", "version": ""})
            elif "windows" in os_.lower():
                queries.append({"host": ip, "product": "windows_server_2019", "vendor": "microsoft", "version": ""})

    return queries


def vulnerability(state: AgentState) -> AgentState:
    """
    Analyze reconnaissance data and identify known vulnerabilities by:
      1. Parsing recon_results to extract host/product/version tuples.
      2. Calling cve_search() for each tuple to get real CVE data from CIRCL.
      3. Passing both the recon context AND the live CVE results to the LLM
         for structured summarization.

    Returns:
        AgentState: Updated state containing `vuln_results`.
    """
    logger.info("Vulnerability agent started")

    recon_results  = state.get("recon_results", {})
    os_fingerprint = state.get("os_fingerprint_results", {})
    xml_content    = state.get("all_xml_content", "")

    # ------------------------------------------------------------------ #
    # Step 1: Extract product/service tuples from recon data              #
    # ------------------------------------------------------------------ #
    queries = _extract_product_queries(recon_results)
    logger.info(f"CVE queries to run: {len(queries)}")

    # ------------------------------------------------------------------ #
    # Step 2: Call cve_search() for each unique (vendor, product) pair    #
    # ------------------------------------------------------------------ #
    seen   = set()
    cve_db = []  # raw results to inject into the LLM prompt

    for q in queries:
        key = (q["vendor"], q["product"])
        if key in seen:
            continue
        seen.add(key)

        try:
            # cve_search is a @tool — call its underlying function directly
            results = cve_search.func(product=q["product"], vendor=q["vendor"])
            if isinstance(results, list) and results:
                cve_db.append({
                    "host":    q["host"],
                    "product": q["product"],
                    "vendor":  q["vendor"],
                    "version": q["version"],
                    "cves":    results,        # [{"id": ..., "summary": ...}, ...]
                })
                logger.info(f"  {q['product']}: {len(results)} CVEs found")
            else:
                logger.info(f"  {q['product']}: no CVEs returned")
        except Exception as e:
            logger.warning(f"  cve_search failed for {q['product']}: {e}")

    # ------------------------------------------------------------------ #
    # Step 3: Ask the LLM to normalize and enrich the combined data       #
    # ------------------------------------------------------------------ #
    vuln_llm_prompt = f"""
    You are a vulnerability analyst. Below is reconnaissance data and real CVE results
    fetched from CIRCL. Your job is to produce a clean, structured JSON array.

    --- Reconnaissance Results ---
    {json.dumps(recon_results, indent=2)}

    --- OS Fingerprinting ---
    {json.dumps(os_fingerprint, indent=2)}

    --- Nmap XML Excerpts ---
    {xml_content[:5000]}

    --- CVE Data (fetched live from CIRCL) ---
    {json.dumps(cve_db, indent=2)}

    Instructions:
    1. For each CVE entry above, output ONE JSON object with these fields:
    - "host"     : IP address of the affected host
    - "product"  : product/service name
    - "version"  : version string (empty string if unknown)
    - "cve_id"   : CVE identifier (e.g. "CVE-2021-44228")
    - "severity" : "Critical" | "High" | "Medium" | "Low" | "Unknown"
    - "summary"  : one-sentence description
    - "exploitable": true | false (your best assessment)
    2. Use the OS fingerprint data to cross-reference hosts to CVEs where possible.
    3. If no CVEs are available for a host/product, omit it — do NOT invent CVEs.
    4. Output a raw JSON array only. No markdown. No explanation.
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