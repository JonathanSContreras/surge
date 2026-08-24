from core.state import AgentState
from core.llm import get_llm
from agents.prompts import REPORTER_SYSTEM_PROMPT
from config.logging_config import get_logger
from api.activity import emit_activity_sync

import json
from langchain.schema import AIMessage, SystemMessage, HumanMessage

logger = get_logger(__name__)

def _invoke_llm(system_prompt: str, human_prompt: str) -> str | None:
    """Call LLM and return content string, or None on empty response."""
    llm = get_llm(tier="analysis")
    result = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt),
    ])
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    return result.content if result.content and result.content.strip() else None


def reporter(state: AgentState) -> AgentState:
    """
    Generates four specialized Markdown reports from aggregated agent data:
      - final_report.md      — complete combined assessment
      - executive_report.md  — CEO / Board / Stakeholders
      - technical_report.md  — CISO / Security Ops
      - public_report.md     — external / press / newsletter
    """
    logger.info("Reporter agent started")
    vuln_count = len(state.get("vuln_normalized_results", []))
    host_count = len(state.get("recon_results", {}).get("discovered_hosts", []))
    emit_activity_sync(
        f"Reporter agent writing Network Security Assessment — {host_count} hosts, {vuln_count} CVEs",
        detail="Compiling reconnaissance, OS analysis, and vulnerability scoring into final_report.md",
        agent_node="reporter",
    )

    recon_agent_results   = state.get("recon_results", {})
    recon_analysis_results = state.get("recon_analysis", "")
    xml_data              = state.get("all_xml_content", "")[:10000]
    os_analysis           = state.get("os_analysis", "")
    vuln_agent_results    = state.get("vuln_normalized_results", [])
    vuln_scoring_results  = state.get("vuln_scoring", [])

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

    # ── 1. Generate the master final report ──────────────────────────────────
    final_content = _invoke_llm(REPORTER_SYSTEM_PROMPT, reporter_prompt)

    if not final_content:
        logger.error("Reporter LLM returned empty content — context window likely exceeded.")
        return {"network_findings": ""}

    run_dir = state["run_dir"]
    with open(f"{run_dir}/final_report.md", "w", encoding="utf-8") as f:
        f.write(final_content)
    logger.info("final_report.md written.")

    # ── 2. Specialized reports are NOT generated here ─────────────────────────
    # Executive/technical/public used to be three more analysis-tier LLM calls
    # in this loop, each re-sending the whole final report as input — four calls
    # per scan whether or not anyone ever opened them. With scans running twice
    # a day unattended that is most of the per-run cost, spent on artefacts
    # nobody may read.
    #
    # They are now generated on demand by POST /reports/generate, which writes
    # the .md into this same run_dir the first time it is asked and reuses it
    # afterwards. Scheduled runs pay for one report; the richer views cost only
    # when a human wants one.
    emit_activity_sync(
        "Final report generated — scan complete",
        event_type="success",
        agent_node="reporter",
        detail="Executive, technical and public reports are generated on demand from the Reports page",
    )
    logger.info("Reporter agent finished all reports.")
    return {"network_findings": final_content}
