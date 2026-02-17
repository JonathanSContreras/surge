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
    vuln_agent_results = state.get("vuln_formatted_results", [])
    vuln_scoring_results = state.get("vuln_scoring", {})

    reporter_prompt = f"""
    You are given the combined outputs of all prior agents in a network vulnerability assessment workflow.

    Data Inputs:

    ### Reconnaissance Data
    {json.dumps(recon_agent_results, indent=2)}

    ### Reconnaissance Analysis
    {recon_analysis_results}

    ### Raw XML Data (first 10,000 chars)
    {xml_data}

    ### Vulnerability Agent Results
    {json.dumps(vuln_agent_results, indent=2)}

    ### Vulnerability Scoring Results
    {json.dumps(vuln_scoring_results, indent=2)}

    ---

    Your Task:

    1. Generate a **complete Network Vulnerability Assessment Report** in markdown.
    2. Include these main sections in order:

    - **Executive Summary (Layman’s Terms)** – Non-technical overview of network health and risks.
    - **Executive Risk Score Block** – Provide a concise summary table or bullet list including:
        - Overall Risk Level (High/Medium/Low)
        - Number of Critical Assets Affected
        - Number of Exploitable Services
        - Top 5 CVEs or vulnerabilities
    - **Technical Summary** – Hosts, OS, ports, and services discovered.
    - **Vulnerability Findings** – Enumerate vulnerabilities per host/service with CVEs, severity, and descriptions.
    - **Risk and Impact Analysis** – Aggregate findings and highlight highest priority risks.
    - **Remediation and Recommendations** – Actionable steps for mitigation.
    - **Appendix** – Optional tables or summaries of raw CVE or scan data.

    3. Ensure:
    - Professional, confident, and factual tone.
    - Correlate vulnerabilities to hosts/services clearly.
    - Executive Risk Score Block is prominently placed at the top for immediate comprehension.
    - Markdown formatting, tables, and bullet lists for readability.
    - No speculation — only summarize what is in the data.
    4. End with a one-paragraph **Final Summary** highlighting overall network risk posture and suggested next steps.
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
    with open(f"./output/{target_ip}_final_report.md", "w", encoding="utf-8") as f:
        f.write(result.content)

    logger.info("Reporter agent finished writing and updated the state.")

    return state