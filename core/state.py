from typing import TypedDict, Any
from core.cve import CVEEntry

## --- AGENTSTATE --- ##
class AgentState(TypedDict):
    ## INPUTS 
    scan_type: str  # e.g. "low"/"medium"/"high"  GIVEN BY USER
    targets: list[str]  # e.g. ["10.10.160.0/24"]  GIVEN BY USER

    ## RECON DATA
    recon_results: dict[str, Any]  # the output would be a json, raw_xml, scan_logs, etc  AFTER RECON AGENT RUNS
    all_xml_content: str
    recon_analysis: str  # RECON ANALYSIS AGENT RUNS

    ## OS DATA
    os_fingerprint_results: dict[str, Any]
    os_xml_content: str
    os_analysis: str  # LLM summary of OS landscape

    ## VULNERABILITY DATA
    vuln_raw_results: list[dict[str, Any]]  # list of CVE vulnerabilities and its score    AFTER VULN AGENT RUNS
    vuln_normalized_results: list[CVEEntry]
    vuln_scoring: list[dict[str, Any]]

    ## RUN METADATA
    run_dir: str  # timestamped output directory for this run

    ## TOPOLOGY DATA
    topology: dict[str, Any]  # network graph built by utils/topology.py: nodes, links, metadata

    ## FINAL OUTPUT
    network_findings: str   # REPORT AGENT CHANGES THIS STATE
