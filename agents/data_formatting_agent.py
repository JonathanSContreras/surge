from core.state import AgentState
from core.llm import get_llm
from agents.prompts import VULN_FORMATTING_SYSTEM_PROMPT
from config.logging_config import get_logger

import json
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# call global log file
logger = get_logger(__name__)

def cvss_data_formatter(state: AgentState) -> AgentState:
    # will format the vulnerability results to the proper format so the XGBoost classifier does not break
    """
    Normalizes vulnerability results into standardized CVEEntry format for ML models.
    """
    logger.info("CVSS data formatting started")

    data_formatter_prompt = """
    Normalize the following raw vulnerability data into the exact schema below.

    Raw Input:
    {raw_input}

    Required Output Schema (STRICT):

    [
    {{
        "cve_id": "CVE-YYYY-NNNNN",
        "mod_date": "YYYY-MM-DD HH:MM:SS",
        "pub_date": "YYYY-MM-DD HH:MM:SS",
        "cvss": 7.5,
        "cwe_code": 89,
        "cwe_name": "CWE name",
        "summary": "Short vulnerability description",
        "access_authentication": "NONE | SINGLE | MULTIPLE",
        "access_complexity": "LOW | MEDIUM | HIGH",
        "access_vector": "NETWORK | ADJACENT | LOCAL",
        "impact_availability": "NONE | PARTIAL | COMPLETE",
        "impact_confidentiality": "NONE | PARTIAL | COMPLETE",
        "impact_integrity": "NONE | PARTIAL | COMPLETE",
        "product": "Detected software",
        "version": "Detected version",
        "host": "IP or hostname"
    }}
    ]

    Instructions:
    - Output JSON only.
    - All objects must include ALL keys above.
    - Use null for unknown values.
    - Preserve host/product/version when present.
    - Ensure consistent data types.
    - Return [] if input is empty or contains no CVEs.
    """

    data_formatter_prompt = data_formatter_prompt.format(
        raw_input=json.dumps(state.get("vuln_raw_results", []), indent=2)
    )

    llm = get_llm()
    result = llm.invoke([
        SystemMessage(content=VULN_FORMATTING_SYSTEM_PROMPT),
        HumanMessage(content=data_formatter_prompt)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["vuln_formatted_results"] = json.loads(result.content)
    print("[cvss_data_formatter] vuln_formatted_results", state["vuln_formatted_results"])

    logger.info("CVSS data formatter has been updated and the state has also been updated.")

    return state