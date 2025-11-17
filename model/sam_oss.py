"""
@author: Brianna Hinds
Description: Agentic System Build
"""

## --- LIBRARIES --- ##
import os
from dotenv import load_dotenv

# Agentic libraries
from typing import TypedDict, Any
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# tools
from tools import nmap_scanning, cve_search, xgboost_data_cleaning, cvss_scorer

# other imports
from globals import TIMEOUT_VAL, SCANNING_DUMP_LOG
from helper import extract_json, summarize_recon_results, xml_parse_v1, all_xml_output_to_txt, target_to_proper_file_name
import json
import time
import datetime
import pandas as pd

## --- LLM DEFINTION --- ##
load_dotenv()
BASE_URL = os.getenv("TAILSCALE_URL")
print(BASE_URL)
llm = ChatOpenAI(
    model="qwen2.5:14b",
    base_url=BASE_URL,
    api_key="ollama",  # this is an unused placeholder (required by SDK)
    temperature=0,
    top_p=1 # makes the model model deterministic
)

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
    vuln_raw_results: list[str]  # list of CVE vulnerabilities and its score    AFTER VULN AGENT RUNS
    vuln_formatted_results: list[CVEEntry]
    vuln_scoring: dict[str, Any]

    ## FINAL OUTPUT
    network_findings: str   # REPORT AGENT CHANGES THIS STATE

## --- AGENT PROMPTS --- ##
from agentic_prompts import RECON_AGENT_SYSTEM_PROMPT, RECON_ANALYSIS_SYSTEM_PROMPT, VULN_AGENT_SYSTEM_PROMPT, VULN_FORMATTING_SYSTEM_PROMPT, REPORTER_SYSTEM_PROMPT


## --- AGENT TOOL BINDING --- ##
vuln_llm_w_tool = llm.bind_tools([cve_search], system_prompt=VULN_AGENT_SYSTEM_PROMPT, return_direct=True)  # return_direct tells the tool binding to return the AI's raw output


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

    # --- VARIABLES ---
    discovered_hosts = set()
    iteration = 0
    max_iterations = 8
    aggregated_logs = []

    no_new_count = 0
    no_new_threshold = 4

    with open(SCANNING_DUMP_LOG, "a") as file:
        file.write(f"Stop variables defined for RECON AGENT:\n----------------\nmax iterations = {max_iterations}\nno_new_threshold = {no_new_threshold}")

    # load previous recon state if exists
    prev = state.get("recon_results", {})
    if prev:
        parsed = prev.get("parsed_network", {})
        discovered_hosts.update(parsed.keys())

    # --- RECON LOOP ---
    while iteration < max_iterations and no_new_count < no_new_threshold:
        iteration += 1

        print(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")

        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")
        ####

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

        raw_text = getattr(raw_decision, "content", str(raw_decision))
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        
        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            print("WRITING TO DUMP LOG in sam_oss.py")
            file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        ####

        # extract json (json = LLM response/output)
        decision = extract_json(raw_text, iteration)

        # --- ROBUST CHECK: fallback and reprompt LLM if the JSON is not found
        if not decision:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON, reprompting model to reformat output...")

            # write to scan dump file
            with open(SCANNING_DUMP_LOG, "a") as file:
                file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON, reprompting model to reformat output...")
            ####

            repair_prompt = f"""
            You previously generated malformed or incomplete JSON.
            Reformat the following into a single, strictly valid JSON object only — no explanations, no markdown, no code fences, and no extra text.

            Rules:
            1. Preserve the existing value of "scan_type" — do not modify it under any circumstances.
            2. The output must follow exactly this schema:

            {{
            "flags": [string],             // list of flag strings
            "targets": {state["targets"]}, // use this exact list (do not alter)
            "scan_type": {state["scan_type"]},
            "reason": "string",
            "max_runtime_s": int
            }}

            Context:
            - Preferred scan_type (from state): "{state['scan_type']}"
            - If uncertain, always use this preferred value.
            - Do not include any extra fields, comments, or formatting.
            - Output one valid JSON object only.

            Text to reformat:
            {raw_text}
            """
            
            repaired = llm.invoke([
                SystemMessage(content=RECON_AGENT_SYSTEM_PROMPT),
                HumanMessage(content=repair_prompt)
            ])

            decision = extract_json(getattr(repaired, "content", str(repaired)), iteration)

            if not decision:
                # if still invalid, move to next iteration
                aggregated_logs.append({
                    "error": "~NO_VALID_JSON",
                    "raw_output": raw_text,
                    "iteration": iteration
                })
                no_new_count += 1
                state["recon_results"] = {
                    "last_log": {},
                    "parsed_network": {},
                    "all_logs": aggregated_logs,
                    "discovered_hosts": list(discovered_hosts),
                    "iteration": iteration
                }
                continue

        # validate decision fields for nmap scan
        flags = decision.get("flags", [])
        dec_targets = decision.get("targets", [])
        max_runtime = decision.get("max_runtime_s", TIMEOUT_VAL)

        if not isinstance(flags, list) or not isinstance(dec_targets, list):
            print(f"~INVALID DECISION: flags={flags}, targets={dec_targets}")
            no_new_count += 1
            continue

        if len(dec_targets) == 0:
            print("~LLM returned no targets, skipping this iteration.")
            no_new_count += 1
            continue

        # run validated nmap scan
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running Nmap scan: {dec_targets}")

        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\nDecision fields have been validated. [{time.strftime('%Y-%m-%d %H:%M:%S')}]\tRunning Nmap scan on {dec_targets} with flags: {flags}.")
        ####

        log = nmap_scanning.invoke({
            "scan_type": decision.get("scan_type", state["scan_type"]),
            "flags": flags,
            "targets": dec_targets,
            # "timeout": min(max_runtime, TIMEOUT_VAL)  # THE max_runtime VALUE THE AGENT IS GIVING IS TO SMALL (making all in-depth scans have timed out)
            "timeout": 1500
        })
        aggregated_logs.append(log)

        # parse nmap scan output (will parse xml file to dictionary)  THIS IS AN ISSUE (the xml content is now the folder name)
        parsed = {}
        print(log.get("xml_file"))
        if log.get("xml_file"):
            parsed = xml_parse_v1(log["xml_file"])  # get into the 

        # detect new hosts
        hosts = set(parsed.keys()) - discovered_hosts
        if hosts:
            print(f"New hosts discovered: {hosts}")

            # write to scan dump file
            with open(SCANNING_DUMP_LOG, "a") as file:
                file.write(f"\nNew hosts discovered: {hosts}")
            ####

            discovered_hosts.update(hosts)
            no_new_count = 0
        else:
            print("~No new hosts found.")

            # write to scan dump file
            with open(SCANNING_DUMP_LOG, "a") as file:
                file.write(f"\n~NO NEW HOSTS DISCOVERED.")
            ####

            no_new_count += 1

        # update agent state
        state["recon_results"] = {
            "last_log": log,
            "parsed_network": parsed,
            "all_logs": aggregated_logs,
            "discovered_hosts": list(discovered_hosts),
            "iteration": iteration
        }

        print(f"Hosts discovered so far: {state['recon_results']['discovered_hosts']}")
        print("aggregated logs:", aggregated_logs)  # debug print (see what is inside)

        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\nHosts discovered so far: {state['recon_results']['discovered_hosts']}\n{aggregated_logs}\n{str(parsed)}")
        ####

        time.sleep(1)

    print(f"Recon finished after {iteration} iterations.")

    # write to scan dump file
    with open(SCANNING_DUMP_LOG, "a") as file:
        file.write(f"Recon finished after {iteration} iterations.")
    ####

    # after recon agent ends run all xml content into a txt file
    xml_dir = state["recon_results"]["xml"]
    xml_content = all_xml_output_to_txt(xml_dir)

    with open(xml_content, "r") as f:
        state["all_xml_content"] += f.read()

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
    with open(f"./output/{target_ip}_recon_analysis.txt", "w") as f:
        f.write(result.content)

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
    You are a vulnerability analysis expert with access to the `cve_search` tool.

    Use it to find real CVE data for products discovered in network reconnaissance.
    Only use the tool when product or service information is available.

    Reconnaissance data:
    {json.dumps(state.get("recon_results", {}), indent=2)}

    Nmap XML (for version and banner references):
    {state.get("all_xml_content", "")[:10000]}

    Steps:
        1. Extract product and version info for each host/service.
        2. For each, use `cve_search(product)` or `cve_search(product, vendor)` to look up real CVEs.
        3. Build a JSON array exactly like this:
        [
            {{
                "host": "<IP>",
                "product": "<product name>",
                "version": "<version>",
                "cve": [
                    {{
                        "id": "<CVE-YYYY-NNNNN>",
                        "summary": "<short English summary>"
                    }}
                ]
            }}
        ]
        - If no CVEs found, include an empty list for "cve".
        - Do not invent vulnerabilities.
        

    Ensure:
    - Use double quotes for all keys and values (valid JSON).
    - If no vulnerabilities are found, output `"cve": []` for that product.
    - Do not add extra commentary or explanation outside the JSON.
    """


    # call the llm
    vuln_result = vuln_llm_w_tool.invoke([
        HumanMessage(content=vuln_llm_prompt)
    ])

    # define the result as an AIMessage and update the state
    vuln_result = AIMessage(vuln_result) if not isinstance(vuln_result, AIMessage) else vuln_result
    state["vuln_raw_results"] = vuln_result.content

    print("Vulnerability agent has ran and updated the state.")

    return state


def cvss_data_formatter(state: AgentState) -> AgentState:
    # will format the vulnerability results to the proper format so the XGBoost classifier does not break
    """
    Normalizes vulnerability results into standardized CVEEntry format for ML models.
    """

    data_formatter_prompt = f"""
    Below is raw vulnerability analysis output. Your task is to cleanly normalize it.

    ### Raw Input:
    {json.dumps(state.get("vuln_raw_results", []), indent=2)}

    ### Expected Output Format (Strict JSON):

    [
      {{
        "cve_id": "CVE-2023-12345",
        "mod_date": "2023-07-10 15:00:00",
        "pub_date": "2023-06-12 10:00:00",
        "cvss": 7.5,
        "cwe_code": "89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "summary": "SQL injection vulnerability in example software allows remote code execution.",
        "access_authentication": "None",
        "access_complexity": "Low",
        "access_vector": "Network",
        "impact_availability": "Partial",
        "impact_confidentiality": "Complete",
        "impact_integrity": "Complete"
      }}
    ]

    ### Instructions:
    - Output must be **valid JSON** (a list of objects).
    - Each object must include all keys shown above.
    - Use null for missing or unknown values.
    - Ensure all field names match exactly.
    - Do not include markdown, commentary, or any explanations outside of the JSON.
    """

    result = llm.invoke([
        SystemMessage(content=data_formatter_prompt),
        HumanMessage(content=VULN_FORMATTING_SYSTEM_PROMPT)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["vuln_formatted_results"] = result.content

    print("CVSS data formatter has been updated and the state has also been updated.")

    return state

def cvss_scoring(state: AgentState) -> AgentState:
    """
    Calls the XGBoost classifier model and outputs the vulnerability with its label.
    """

    vuln_data = state["vuln_formatted_results"]

    cwe = vuln_data["cwe_code"] 
    cwe_name = vuln_data["cwe_name"],
    summary = vuln_data["summary"],
    acces_auth = vuln_data["access_authentication"]
    acces_complex = vuln_data["access_complexity"]
    acces_vec = vuln_data["access_vector"]
    impa_avail = vuln_data["impact_availability"]
    impa_confid = vuln_data["impact_confidentiality"]
    impa_integ = vuln_data["impact_integrity"]

    vuln_df = pd.DataFrame(
        [cwe, cwe_name, summary, acces_auth, acces_complex, acces_vec, impa_avail, impa_confid, impa_confid, impa_integ]
    )
    print(vuln_df.head())
    categy_cols = ["access_authentication", "access_complexity", "access_vector", "impact_availability", "impact_confidentiality", "impact_integrity"]
    cve_data = xgboost_data_cleaning(vuln_df, categy_cols, "summary")
    print("cve_data output:", cve_data)

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
    with open(f"./output/{target_ip}_final_report.txt", "w") as f:
        f.write(result.content)

    print("Reporter agent finished writing and updated the state.")

    return state


## --- GRAPH DEFINITION --- ##
workflow = StateGraph(AgentState)
workflow.add_node("recon", recon)
workflow.add_node("recon_analysis", recon_analysis)
workflow.add_node("vulnerability", vulnerability)
workflow.add_node("cvss_data_formatter", cvss_data_formatter) 
workflow.add_node("cvss_scorer", cvss_scoring) 
workflow.add_node("supervisor", reporter)

workflow.add_edge("recon", "recon_analysis")
# workflow.add_edge("recon_analysis", END)  # TEST EDGE
workflow.add_edge("recon_analysis", "supervisor")
workflow.add_edge("recon", "vulnerability")
workflow.add_edge("vulnerability", "cvss_data_formatter")
workflow.add_edge("cvss_data_formatter", "cvss_scorer")
workflow.add_edge("cvss_scorer", "supervisor")
workflow.add_edge("supervisor", END)

workflow.set_entry_point("recon")

sam = workflow.compile()

if __name__ == "__main__":
    start_time = time.perf_counter()
    initial_state = {
        "scan_type": "high",
        "targets": ["10.10.162.0/24"],  # whole subnet scan  ["10.10.162.0/24"]
        "recon_results": {},
        "all_xml_content": "",
        "recon_analysis": "",
        "vuln_raw_results": [],
        "vuln_formatted_results": [],
        "vuln_scoring": {},
        "network_findings": ""
    }

    ## FINAL OUTPUT
    network_findings: str   # REPORT AGENT CHANGES THIS STATE

    results = sam.invoke(initial_state)
    
    # string print
    print(results)

    # json dump
    print(json.dumps(results, indent=2))

    time_in_minutes = (time.perf_counter()-start_time) / 60

    print(f"Code finished in {time_in_minutes} minutes.")