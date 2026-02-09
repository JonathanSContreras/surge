"""
@author: Brianna Hinds
Description: Agentic System Build  (~main.py)
"""

## --- LIBRARIES --- ##
import os
from dotenv import load_dotenv

# agentic libraries
from typing import TypedDict, Any
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# tools
from tools import nmap_scanning, cve_search, xgboost_data_cleaning, cvss_scorer

# other imports
from globals import TIMEOUT_VAL, SCANNING_DUMP_LOG, RECON_CONVERGENCE
from helper import extract_json, xml_parse_v1, all_xml_output_to_txt, target_to_proper_file_name
import json
import time
import datetime
import pandas as pd

## --- LLM DEFINTION --- ##
load_dotenv()
BASE_URL = os.getenv("TAILSCALE_URL")
print(BASE_URL)
llm = ChatOpenAI(
    # model="qwen2.5:14b",
    base_url=BASE_URL,
    model="gpt-oss:20b",
    api_key="ollama",  # this is an unused placeholder value (required by SDK)
    temperature=0,
    top_p=1 # makes the model model deterministic
)

# data structure class build for the CVE entry data
class CVEEntry(TypedDict, total=False):
    cve_id: str
    mod_date: str
    pub_date: str
    cvss: float
    cwe_code: str
    cwe_name: str
    summary: str
    access_authentication: str
    access_complexity: str
    access_vector: str
    impact_availability: str
    impact_confidentiality: str
    impact_integrity: str

## --- AGENTSTATE --- ##
class AgentState(TypedDict):
    ## INPUTS 
    scan_type: str  # e.g. "low"/"medium"/"high"  GIVEN BY USER
    targets: list[str]  # e.g. ["10.10.160.0/24"]  GIVEN BY USER

    ## RECON DATA
    recon_results: dict[str, Any]  # the output would be a json, raw_xml, scan_logs, etc  AFTER RECON AGENT RUNS
    all_xml_content: str
    recon_analysis: str  # RECON ANALYSIS AGENT RUNS

    ## VULNERABILITY DATA
    vuln_raw_results: list[dict[str, Any]]  # list of CVE vulnerabilities and its score    AFTER VULN AGENT RUNS
    vuln_formatted_results: list[CVEEntry]
    vuln_scoring: dict[str, Any]

    ## FINAL OUTPUT
    network_findings: str   # REPORT AGENT CHANGES THIS STATE


def build_mas_graph():
    """
    Graph outline for the MAS.
    """

    workflow = StateGraph(AgentState)

    workflow.add_node("recon", recon)
    workflow.add_node("recon_analysis", recon_analysis)
    workflow.add_node("vulnerability", vulnerability)
    workflow.add_node("cvss_data_formatter", cvss_data_formatter) 
    workflow.add_node("cvss_scorer", cvss_scoring) 
    workflow.add_node("reporter", reporter)
    
    workflow.set_entry_point("recon")

    workflow.add_edge("recon", "recon_analysis")
    # workflow.add_edge("recon_analysis", END)  # TEST EDGE
    workflow.add_edge("recon_analysis", "vulnerability")
    workflow.add_edge("vulnerability", "cvss_data_formatter")
    workflow.add_edge("cvss_data_formatter", "cvss_scorer")
    workflow.add_edge("cvss_scorer", "reporter")
    workflow.add_edge("reporter", END)

    return workflow.compile()


## --- AGENT PROMPTS --- ##
from agentic_prompts import RECON_AGENT_SYSTEM_PROMPT, RECON_ANALYSIS_SYSTEM_PROMPT, VULN_AGENT_SYSTEM_PROMPT, VULN_FORMATTING_SYSTEM_PROMPT, REPORTER_SYSTEM_PROMPT


## --- AGENT TOOL BINDING --- ##


## --- AGENT DEFINITIONS --- ##
def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# RECON AGENT #
def recon(state: AgentState) -> AgentState:
    """
    Progressive recon loop that calls nmap commands to map out the full network. 
    Identifies open ports, devices, etc.
    Repeat until stop condition is met or no new hosts are found.
    """

    ## STATE INITIALIZATION
    state.setdefault("recon_seen_hosts", set())
    state.setdefault("recon_seen_ports", set())
    state.setdefault("recon_seen_services", set())
    state.setdefault("recon_no_change_count", 0)
    state.setdefault("recon_start_time", time.time())

    # --- VARIABLES ---
    discovered_hosts = state["recon_seen_hosts"]
    aggregated_logs = []
    iteration = 0

    with open(SCANNING_DUMP_LOG, "a") as file:
        file.write(f"STARTING RECON AGENT:\n----------------\nmax iterations = {RECON_CONVERGENCE['max_iterations']}\nmax no change iterations = {RECON_CONVERGENCE['max_no_change_iterations']}\ntime budget (s): {RECON_CONVERGENCE['time_budget_seconds']}")

    # --- MAIN RECON LOOP ---
    while True:
        iteration += 1
        # HARD CONVERGENCE
        if (iteration > RECON_CONVERGENCE["max_iterations"]
            or state["recon_no_change_count"] >= RECON_CONVERGENCE["max_no_change_iterations"]
            or time.time() - state["recon_start_time"] > RECON_CONVERGENCE["time_budget_seconds"]):
            print("Hard recon convergence reached, stopping RECON AGENT.")
            break

        # write to scan dump file
        print(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")  # sanity print
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")
        ####

        # LLM DECISIONS
        if state["recon_no_change_count"] > 0:
            print("No new data last iteartion (skipping LLM escalation).")
            continue

        # prompt LLM to ensure correct output
        llm_input = f"""
        You are an autonomous network reconnaissance specialist.
        You MUST use the previous scan_type when responding unless explicitly changing strategy.
        You MUST produce only JSON in the specified schema, no explanations, code fences, or extra text.

        ### Context summary
        - Known hosts discovered so far: {len(discovered_hosts)}
        - Total scan iterations completed: {len(aggregated_logs)}
        - Active targets under analysis: {', '.join(state['targets'])}
        - Last scan_type: {state['scan_type']}


        ### Adaptive Scanning Rules
        1. **Low scans**: Host discovery only (`-sn`). Use for new subnets or fallback scans.
        2. **Medium scans**: Targeted port/service enumeration (`-sS`, `-sV`, `-O`). Collect banners, OS info, and light scripts (`-sC`).
        3. **High scans**: Aggressive, deep scans (`-A`, `--script vuln`, `-O`, `-sV`, full port range). Collect all metadata, vulnerability info, and OS fingerprints.

        - Escalate automatically if new hosts or services are discovered and metadata is incomplete.
        - Switch strategies automatically if no new hosts or open ports are found after 2 iterations.
        - Always prefer narrow incremental scans first, and avoid repeating the same scan on unchanged hosts.
        - Adjust timing (`-T`), port ranges (`-p`, `--top-ports`), and protocols (`-sS`, `-sU`) according to scan_type.
        - When in high scans, always include at least one vuln script (`--script vuln` or other default nmap scripts) and metadata flags (`-O`, `--traceroute`, `--reason`).

        ### Output Requirements
        - `flags`: nmap flags appropriate to scan_type
        - `targets`: hosts or CIDRs to focus on
        - `scan_type`: maintain current scan_type unless escalating
        - `reason`: concise rationale for this scan decision
        - `max_runtime_s`: upper limit for scan duration, based on the flags you provide give a resonable amount of time to scan
        - `escalation`: "none", "service_scan", or "deep_scan"

        ### JSON Schema Example
        {{
        "flags": [string],
        "targets": [string],
        "scan_type": "{state['scan_type']}",
        "reason": "string",
        "max_runtime_s": int,
        "escalation": "none" | "service_scan" | "deep_scan"
        }}

        Respond **only** with valid JSON matching this schema.
        """

        # ask LLM for scan descision (gpt oss needs it in a chat message list form)
        raw_decision: AIMessage = llm.invoke([
            SystemMessage(content=RECON_AGENT_SYSTEM_PROMPT),
            HumanMessage(content=json.dumps(llm_input))
        ])

        # write to scan dump file
        raw_text = getattr(raw_decision, "content", str(raw_decision))
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        with open(SCANNING_DUMP_LOG, "a") as file:
            print("WRITING TO DUMP LOG in sam_oss.py")
            file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        ####

        # extract json (json = LLM response/output)
        # decision = extract_json(raw_text, iteration)
        decision = extract_json(raw_text, iteration)
        if not isinstance(decision, dict):
            decision = {}


        # --- ROBUST CHECK: fallback and reprompt LLM if the JSON is not found
        if not decision:
            # write to scan dump file
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON,skipping iteartion...")
            with open(SCANNING_DUMP_LOG, "a") as file:
                file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON, skipping iteration...")
            ####

            state["recon_no_change_count"] += 1
            continue

        # validate decision fields for nmap scan (have robust data type structure)
        flags = decision.get("flags", [])
        dec_targets = decision.get("targets", [])
        # timeout = decision.get("max_runtime_s", TIMEOUT_VAL)

        if not flags or not dec_targets:
            print(f"~DECISION MISSING FLAGS OR TARGETS: flags={flags}, targets={dec_targets}")
            state["recon_no_change_count"] += 1
            continue

        # run validated nmap scan
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running Nmap scan: {dec_targets}")

        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\nDecision fields have been validated. [{time.strftime('%Y-%m-%d %H:%M:%S')}]\tRunning Nmap scan on {dec_targets} with flags: {flags}.")
        ####

        # RUN NMAP
        log = nmap_scanning.invoke({
            "scan_type": decision.get("scan_type", state["scan_type"]),
            "flags": flags,
            "targets": dec_targets,
            # "timeout": min(max_runtime, TIMEOUT_VAL)  # THE max_runtime VALUE THE AGENT IS GIVING IS TO SMALL (making all in-depth scans have timed out)
            "timeout": TIMEOUT_VAL
        })
        aggregated_logs.append(log)

        # parse nmap scan output (will parse xml file to dictionary)  THIS IS AN ISSUE (the xml content is now the folder name)
        parsed = {}
        # print("log.print xml", type(log.get("xml_file")))
        if log.get("success"):
            parsed = xml_parse_v1(f"{log['xml_dir']}/{log['xml_file']}")  # NOTE: might need to concate the folder name and file name
            # print("parsing", parsed)

        # DELTA DETECTION
        new_hosts = set(parsed.keys()) - discovered_hosts
        new_ports = set()
        new_services = set()

        for host, host_data in parsed.items():
            for svc in host_data.get("services", []):
                port_id = f"{host}:{svc.get('port')}"
                svc_id = f"{svc.get('product')}:{svc.get('version')}"

                if port_id not in state["recon_seen_ports"]:
                    new_ports.add(port_id)

                if svc_id not in state["recon_seen_services"]:
                    new_services.add(svc_id)

        # UPDATE STATE + CONVERGENCE
        if new_hosts or new_ports or new_services:
            print(
                f"New discovery — hosts:{len(new_hosts)} "
                f"ports:{len(new_ports)} services:{len(new_services)}"
            )
            discovered_hosts.update(new_hosts)
            state["recon_seen_ports"].update(new_ports)
            state["recon_seen_services"].update(new_services)
            state["recon_no_change_count"] = 0
        else:
            print("No new hosts, ports, or services.")
            state["recon_no_change_count"] += 1

        # UPDATE AGENT STATE
        state["recon_results"] = {
            "last_log": log,
            "parsed_network": parsed,
            "all_logs": aggregated_logs,
            "discovered_hosts": list(discovered_hosts),
            "iteration": iteration,
        }

        time.sleep(1)

    # FINAL XML AGGREGATION
    xml_dirs = [
        log["xml_dir"]
        for log in state["recon_results"]["all_logs"]
        if log.get("success") and log.get("xml_dir")
    ]

    if xml_dirs:
        xml_content_path = all_xml_output_to_txt(xml_dirs[0])
        with open(xml_content_path, "r", encoding="utf-8") as f:
            state["all_xml_content"] += f.read()

    print("Recon agent finished cleanly.")
    return state


def recon_analysis(state: AgentState) -> AgentState:  # this will be a simple "here llm analyze this (no tools needed)"
    """
    Perform high-level reconnaissance analysis using LLM reasoning.

    This agent reviews previous Nmap scan results, historical scan logs, 
    and parsed XML output to generate a concise but structured summary 
    of the network environment. The goal is to interpret findings, 
    identify patterns, and suggest next steps for further investigation.

    Parameters
    ----------
    state : AgentState
        The current pipeline state dictionary. Expected keys include:
        - "recon_results": dict containing structured results of prior scans,
          including any parsed XML summaries.
        - "recon_results.parsed_network": structured data or a path to the
          parsed XML network map.
    
    Returns
    -------
    AgentState
        The updated state object with a new key "network_findings" containing
        the LLM-generated textual analysis.
    
    Notes
    -----
    - This function does not run any active scanning; it only performs
      passive analysis of existing data.
    - LLM responses are stringified for consistency and stored under
      state["network_findings"].
    - The LLM should interpret logs and recon data to:
        • Summarize discovered hosts, ports, and services
        • Highlight anomalies or noteworthy findings
        • Suggest next scan strategies or validation steps
    """

    # define what things the analysis agent will need to give for a full analysis
    recon_results = state["recon_results"]

    # read text file and put in logs variable
    with open(SCANNING_DUMP_LOG, "r") as log_file:
        logs = log_file.read()

    # all xml output (already outputted in a file)
    xml_file = state["all_xml_content"]
    # xml_output_path = f"{state["recon_results"]["xml"]}/xml_content.txt"
    # with open(xml_output_path, "r") as f:
    #     xml_file = f.read()

    print(xml_file)
    print(logs)

    # define the agent's prompt
    analysis_prompt = f"""
    You are a network reconnaissance analyst.

    Below are the inputs for your analysis:
    -------------------------
    SCAN LOG SUMMARY:
    {logs}

    PARSED NETWORK MAP (from Nmap XML):
    {xml_file}

    STRUCTURED RECON RESULTS:
    {json.dumps(recon_results, indent=2)}
    -------------------------

    TASK:
    1. Provide a detailed technical summary of the current network.
    2. Identify key hosts, open ports, service fingerprints, and any other important information.
    3. Describe potential next recon steps (e.g., higher-tier scans, 
       service enumeration, OS detection, or validation scans).
    4. Mention any anomalies or inconsistencies in scan results.
    
    Format your answer as:
    Network Summary:
    (text)

    Key Observations:
    (text)

    Recommended Next Actions:
    (text)
    """

    # call the llm
    result = llm.invoke([
        SystemMessage(content=RECON_ANALYSIS_SYSTEM_PROMPT),
        HumanMessage(content=analysis_prompt)
    ])

    # check if result answer is a string
    print(type(result))
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["recon_analysis"] = result.content

    # write the analysis into a txt file
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./output/{target_ip}_recon_analysis.txt", "w", encoding="utf-8") as f:
        f.write(result.content)

    print(state["recon_analysis"])

    print("Recon analysis agent finished analysis and updated the state.")

    return state


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


    # CAN EITHER PROMPT TO DO THE CVSS SCORE OR NOT (CLASSIFIER WILL DO THAT)

    vuln_llm_prompt = f"""
    Analyze the following reconnaissance data and identify REAL CVEs
    associated with detected products and versions.

    Reconnaissance results:
    {json.dumps(state.get("recon_results", {}), indent=2)}

    Nmap XML excerpts (for banner/version context):
    {state.get("all_xml_content", "")[:10000]}

    Instructions:
    1. Extract product name, version, and host IP for each discovered service.
    2. Use known public CVE knowledge (NVD, MITRE, CIRCL-style data).
    3. Output ONE JSON ARRAY where EACH OBJECT IS A SINGLE CVE.
    4. Populate all schema fields where possible.
    5. If no vulnerabilities are found, return [].

    Remember:
    - Output JSON only.
    - No markdown.
    - No explanations.
    - No nested structures.
    """

    # call the llm
    vuln_result = llm.invoke([
        SystemMessage(content=VULN_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=vuln_llm_prompt)
    ])

    ## ADDED 
    raw = vuln_result.content
    parsed = extract_json(raw)

    if not isinstance(parsed, list):
        print("~ Vulnerability agent returned invalid JSON, defaulting to []")
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

    print("Vulnerability agent has ran and updated the state.")

    return state


def cvss_data_formatter(state: AgentState) -> AgentState:
    # will format the vulnerability results to the proper format so the XGBoost classifier does not break
    """
    Normalizes vulnerability results into standardized CVEEntry format for ML models.
    """

    # data_formatter_prompt = f"""
    # Normalize the following raw vulnerability data into the exact schema below.

    # Raw Input:
    # {json.dumps(state.get("vuln_raw_results", []), indent=2)}

    # Required Output Schema (STRICT):

    # [
    # {
    #     "cve_id": "CVE-YYYY-NNNNN",
    #     "mod_date": "YYYY-MM-DD HH:MM:SS",
    #     "pub_date": "YYYY-MM-DD HH:MM:SS",
    #     "cvss": 7.5,
    #     "cwe_code": 89,
    #     "cwe_name": "CWE name",
    #     "summary": "Short vulnerability description",
    #     "access_authentication": "None | Single | Multiple",
    #     "access_complexity": "Low | Medium | High",
    #     "access_vector": "Network | Adjacent | Local",
    #     "impact_availability": "None | Partial | Complete",
    #     "impact_confidentiality": "None | Partial | Complete",
    #     "impact_integrity": "None | Partial | Complete",
    #     "product": "Detected software",
    #     "version": "Detected version",
    #     "host": "IP or hostname"
    # }
    # ]

    # Instructions:
    # - Output JSON only.
    # - All objects must include ALL keys above.
    # - Use null for unknown values.
    # - Preserve host/product/version when present.
    # - Ensure consistent data types (numbers as numbers, not strings).
    # - Return [] if input is empty or contains no CVEs.
    # """

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
        "access_authentication": "None | Single | Multiple",
        "access_complexity": "Low | Medium | High",
        "access_vector": "Network | Adjacent | Local",
        "impact_availability": "None | Partial | Complete",
        "impact_confidentiality": "None | Partial | Complete",
        "impact_integrity": "None | Partial | Complete",
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


    result = llm.invoke([
        SystemMessage(content=VULN_FORMATTING_SYSTEM_PROMPT),
        HumanMessage(content=data_formatter_prompt)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["vuln_formatted_results"] = json.loads(result.content)

    print("CVSS data formatter has been updated and the state has also been updated.")

    return state

def cvss_scoring(state: AgentState) -> AgentState:
    """
    Calls the XGBoost classifier model and outputs the vulnerability with its label.
    """

    vuln_list = state["vuln_formatted_results"]  # list object

    for vuln_data in vuln_list:
        cwe = vuln_data.get("cwe_code")
        cwe_name = vuln_data.get("cwe_name")
        summary = vuln_data.get("summary")
        access_auth = vuln_data.get("access_authentication")
        access_complex = vuln_data.get("access_complexity")
        access_vec = vuln_data.get("access_vector")
        impa_avail = vuln_data.get("impact_availability")
        impa_confid = vuln_data.get("impact_confidentiality")
        impa_integ = vuln_data.get("impact_integrity")

        vuln_df = pd.DataFrame([
            {
                "cwe": cwe, 
                "cwe_name": cwe_name, 
                "summary": summary, 
                "access_authentication": access_auth,
                "access_complexity": access_complex, 
                "access_vector": access_vec, 
                "impact_availability": impa_avail, 
                "impact_confidentiality": impa_confid, 
                "impact_integrity": impa_integ

            }]
        )
        # print(vuln_df.head())
        catgy_cols = ["access_authentication", "access_complexity", "access_vector", "impact_availability", "impact_confidentiality", "impact_integrity"]
        cve_data = xgboost_data_cleaning(vuln_df, catgy_cols)
        print("cve_data output:", cve_data)
        cve_data.to_csv("cvs_data.csv", index=False)

        # will need to take the formatted data and output a score
        vulnerability_score = cvss_scorer(cve_data)

        print("vulnerability score:", vulnerability_score)

        state["vuln_scoring"] = vulnerability_score

    print("CVSS scoring agent has completed running and the state is updated.")

    return state

def reporter(state: AgentState) -> AgentState:  # takes all output from all agents
    """
    Takes ALL data from the AgentState, and defines a final network analysis report of all findings. 
    """

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

    result = llm.invoke([
        SystemMessage(content=REPORTER_SYSTEM_PROMPT),
        HumanMessage(content=reporter_prompt)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["network_findings"] = result.content

    # write the analysis into a txt file
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./output/{target_ip}_final_report.txt", "w", encoding="utf-8") as f:
        f.write(result.content)

    print("Reporter agent finished writing and updated the state.")

    return state


## --- GRAPH DEFINITION --- ##
sam = build_mas_graph()

if __name__ == "__main__":
    start_time = time.perf_counter()

    ## CLEAN scan_dumps.txt BEFORE EVERY RUN
    initial_state = {
        "scan_type": "high",
        "targets": ["192.168.1.0/24"],  # whole subnet scan  ["10.10.162.0/24"]
        "recon_results": {},
        "all_xml_content": "",
        "recon_analysis": "",
        "vuln_raw_results": [],
        "vuln_formatted_results": [],
        "vuln_scoring": {},
        "network_findings": ""
    }

    ## FINAL OUTPUT
    # network_findings: str   # REPORT AGENT CHANGES THIS STATE  CONFUSED ABOUT THIS LINE LOL

    results = sam.invoke(initial_state)
    
    # string print
    print(results)

    # json dump
    print(json.dumps(results, indent=2))

    time_in_minutes = (time.perf_counter()-start_time) / 60

    print(f"Code finished in {time_in_minutes} minutes.") 
    # NOTE: full run at my home took 35 minutes
    print(results["network_findings"])