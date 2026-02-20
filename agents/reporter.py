from core.state import AgentState
from core.llm import get_llm
from agents.prompts import REPORTER_SYSTEM_PROMPT
from utils.helpers import target_to_proper_file_name
from config.logging_config import get_logger

import json
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# call global log file
logger = get_logger(__name__)

def reporter(state: AgentState) -> AgentState:  # takes all output from all agents
    """
    Takes ALL data from the AgentState, and defines a final network analysis report of all findings. 
    """
    logger.info("Reporter agent started")

    # define all data to take in
    recon_agent_results = state.get("recon_results", {})
    recon_analysis_results = state.get("recon_analysis", "")
    xml_data = state.get("all_xml_content", "")[:10000]
    os_fingerprint_results = state.get("os_fingerprint_results", {})
    os_analysis = state.get("os_analysis", "")
    vuln_agent_results = state.get("vuln_normalized_results", [])
    vuln_scoring_results = state.get("vuln_scoring", [])


    reporter_prompt = f"""
    Below is the complete aggregated data from a multi-agent network security workflow.

    You MUST generate a comprehensive Markdown Network Security Assessment Report
    using ONLY the information provided below.

    -------------------------
    RECONNAISSANCE DATA
    -------------------------
    {json.dumps(recon_agent_results, indent=2)}

    -------------------------
    RECONNAISSANCE ANALYSIS
    -------------------------
    {recon_analysis_results}

    -------------------------
    OPERATING SYSTEM FINGERPRINT DATA
    -------------------------
    {json.dumps(os_fingerprint_results, indent=2)}

    -------------------------
    OPERATING SYSTEM ANALYSIS
    -------------------------
    {os_analysis}

    -------------------------
    VULNERABILITY FINDINGS (Formatted)
    -------------------------
    {json.dumps(vuln_agent_results, indent=2)}

    -------------------------
    VULNERABILITY SCORING DATA
    -------------------------
    {json.dumps(vuln_scoring_results, indent=2)}

    -------------------------
    RAW XML SNIPPET (Truncated)
    -------------------------
    {xml_data}

    -------------------------

    REPORT GENERATION INSTRUCTIONS:

    1. Generate a structured Markdown report with all required sections.
    2. Correlate:
    - Hosts → Services → Vulnerabilities → Scores
    3. Calculate counts where possible (e.g., number of hosts, total vulnerabilities).
    4. If no vulnerabilities exist, clearly state that in the Vulnerability Findings section.
    5. Ensure the Executive Risk Score Block appears immediately after the Executive Summary.
    6. Use Markdown tables for:
    - Executive Risk Score Block
    - Vulnerability summaries
    - Host/service listings (if useful)
    7. Do NOT include any explanation outside of the report.
    8. Do NOT include JSON.
    9. Do NOT include code fences.
    10. The output must begin with a Markdown title:

    # Network Security Assessment Report

    End with a one-paragraph **Final Summary** describing overall security posture and next steps.
    """

    llm = get_llm()
    result = llm.invoke([
        SystemMessage(content=REPORTER_SYSTEM_PROMPT),
        HumanMessage(content=reporter_prompt)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["network_findings"] = result.content

    # write the analysis into a txt file
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./report/{target_ip}_final_report.md", "w", encoding="utf-8") as f:
        f.write(result.content)

    logger.info("Reporter agent finished writing and updated the state.")

    return state