from core.state import AgentState
from core.llm import get_llm
from execution.json_extract import extract_json
from agents.prompts import VULN_AGENT_SYSTEM_PROMPT
from config.logging_config import get_logger

import json
from langchain.schema import SystemMessage, HumanMessage

# call global log file
logger = get_logger(__name__)

def vulnerability(state: AgentState) -> AgentState:
    """
    Analyze reconnaissance data and identify known vulnerabilities.

    This function takes the agent's current state, including:
      - `state["recon_results"]`: structured output from prior network/service scans
      - `state["all_xml_content"]`: raw stringified XML data from recon tools (e.g., Nmap)

    It constructs a vulnerability-analysis prompt and queries the LLM (or a local CVE lookup system)
    to generate a summarized vulnerability dataset for each discovered host and service.

    Expected output format in `state["vuln_results"]`:
        [
            {
                "host": "192.168.1.10",
                "product": "Apache httpd",
                "version": "2.4.57",
                "cve": [
                    {
                        "id": "CVE-2023-12345",
                        "summary": "Remote code execution in mod_proxy"
                    }
                ]
            },
            ...
        ]

    Notes:
      - This function **must not perform any external network calls** (e.g., to NVD or CVE APIs).
        If external data is needed, it should come from a preloaded local database or an offline index.
      - The LLM may summarize or format CVE data, but the CVE identifiers and descriptions should
        originate from authoritative CVE datasets (e.g., NVD, OSV, MITRE).
      - The function updates the agent state in place and returns it.

    Returns:
        AgentState: Updated state containing `vuln_results`.
    """
    logger.info("Vulnerability agent started")

    vuln_llm_prompt = f"""
    Analyze the following reconnaissance data and identify REAL CVEs
    associated with detected products and versions.

    Reconnaissance results:
    {json.dumps(state.get("recon_results", {}), indent=2)}

    OS Fingerprinting Results:
    {json.dumps(state.get("os_fingerprint_results", {}), indent=2)}

    Nmap XML excerpts (for banner/version context):
    {state.get("all_xml_content", "")[:10000]}

    Instructions:
    1. Extract product name, version, and host IP for each discovered service.
    2. **Use OS information to prioritize OS-specific vulnerabilities.**
    3. Cross-reference CPE identifiers from OS detection with known CVEs.
    4. Use known public CVE knowledge (NVD, MITRE, CIRCL-style data).
    5. Output ONE JSON ARRAY where EACH OBJECT IS A SINGLE CVE.
    6. Populate all schema fields where possible.
    7. If no vulnerabilities are found, return [].

    Remember:
    - Output JSON only.
    - No markdown.
    - No explanations.
    - No nested structures.
    """

    # call the llm
    llm = get_llm()
    vuln_result = llm.invoke([
        SystemMessage(content=VULN_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=vuln_llm_prompt)
    ])

    ## ADDED 
    raw = vuln_result.content
    parsed = extract_json(raw)

    if not isinstance(parsed, list):
        logger.info("~ Vulnerability agent returned invalid JSON, defaulting to []")
        parsed = []

    state["vuln_raw_results"] = parsed

    ####
    # # # call the llm
    # # vuln_result = vuln_llm_w_tool.invoke([
    # #     HumanMessage(content=vuln_llm_prompt)
    # # ])

    # # define the result as an AIMessage and update the state
    # vuln_result = AIMessage(vuln_result) if not isinstance(vuln_result, AIMessage) else vuln_result
    # state["vuln_raw_results"] = json.loads(vuln_result.content)

    logger.info("Vulnerability agent has ran and updated the state.")

    return state