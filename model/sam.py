"""
@author: Brianna Hinds
Description: Agentic System Build
"""

## --- LIBRARIES --- ##
import os
from dotenv import load_dotenv

# Agentic libraries
from typing import TypedDict, Any
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END
from langchain_core import bi

# tools
from tools import nmap_scanning ,xml_parse

# other imports
import json
import time


## --- GLOBAL VARIABLES --- ##
TIMEOUT_VAL = 300

## --- LLM DEFINTION --- ##
load_dotenv()
API = os.getenv("GOOGLE_API_KEY")
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=API,
    temperature=0
)

## --- AGENTSTATE --- ##
class AgentState(TypedDict):
    targets: list[str]  # would target be a list or string, given we have access to the network?
    recon_results: dict[str, Any]  # the output would be a json, raw_xml, scan_logs, etc
    vuln_results: list[str]  # list of CVE vulnerabilities and its score
    network_findings: str

## --- AGENT PROMPTS --- ##
RECON_SYSTEM_PROMPT = """
You are a recon agent with authorized access to the target network (the user has permission).
Your job: create *structured* nmap scan decisions to discover the full network progressively.
Output MUST be valid JSON with keys:
  {
    "flags": ["-sn" | "-sS" | "-sV" | "-p1-1024" | ...],
    "targets": ["CIDR or IP strings"],
    "reason": "<brief human-friendly reason>",
    "max_runtime_s": <integer seconds, optional>,
    "escalation": "none" | "service_scan" | "deep_scan"
  }

Constraints:
 - Allowed flags: -sn, -sS, -sT, -sU, -sV, -O, -p1-65535 (or narrower), -Pn, -T0 -T4, -oX -
 - Do NOT include shell operators
 - Keep expected runtime reasonable (default < 300s). Set max_runtime_s only if special reason.
 - Prefer small incremental scans: host discovery first, then targeted port/service scans on newly discovered hosts.
 - If the network is large, suggest scanning subnets (CIDR) rather than entire routable ranges.
Example:
  {"flags":["-sn","-T4"], "targets":["192.168.1.0/24"], "reason":"fast host discovery", "max_runtime_s":120, "escalation":"none"}
"""  # needs to be defined in a way where the agent knows it has authorized access to the network 
RECON_ANALYSIS_SYSTEM_PROMPT = """"""

## --- AGENT TOOL BINDING --- ##
recon_llm = llm.bind_tools([], system_prompt=RECON_SYSTEM_PROMPT)  # return_direct=True?


## --- AGENT DEFINITIONS --- ##
def recon(state: AgentState) -> AgentState:
    """
    Progressive recon loop that calls nmap commands to map out the full network. 
    Identifying open ports, devices, etc.
    Repeat until stop condition is met.
    """

    # define initial variables
    discovered_hosts = set()
    iteration = 0
    max_iterations = 8
    no_new_count = 0
    no_new_threshold = 2

    # use previous recon results
    prev = state.get("recon_results", {})
    if prev:
        parsed = prev.get("parsed_network", {})
        discovered_hosts.update(parsed.keys())
    
    # define a stop condition for the looping
    aggregated_logs = []
    while iteration < max_iterations and no_new_count < no_new_threshold:
        iteration += 1

        # prompt content
        llm_input = {
            "known_hosts": list(discovered_hosts)[:200],  # cap the size
            "scan_history": [l.get("command") for l in aggregated_logs[- 5:]],
            "targets": state["targets"]
        }

        # ask LLM for next scan JSON
        raw_decision = recon_llm.invoke(json.dumps(llm_input))

        # parse the JSON (safely)
        try:
            decision = json.loads(raw_decision) if isinstance(decision, str) else raw_decision
        except Exception as e:  # if it hits this the the output cannot be parsed
            break

        # validate decision
        flags = decision.get("flags", [])
        dec_targets = decision.get("targets", [])
        max_runtime = decision.get("runtime_s", TIMEOUT_VAL)

        if not isinstance(flags, list) or not isinstance(dec_targets, list) or len(dec_targets) == 0:
            break

        # run the validated nmap
        log = nmap_scanning(flags, dec_targets, min(max_runtime, TIMEOUT_VAL))
        aggregated_logs.append(log)

        # parse xml
        parsed = {}
        if log.get("xml"):
            parsed = xml_parse(log["xml"])  # might need to define xml parser from string

        # detect new hosts
        hosts = set(parsed.keys()) - discovered_hosts
        if hosts:
            discovered_hosts.update(hosts)
            no_new_count = 0
        else: # nothing new was found
            no_new_count += 1

        # update state
        state["recon_results"] = {
            "last_log": log,
            "parsed_network": parsed,
            "all_logs": aggregated_logs,
            "discovered_host": list(discovered_hosts),
            "iteration": iteration
        }

    time.sleep(1)
    return state

def recon_analysis(state: AgentState) -> AgentState:
    # takes state["recon_results"]["parsed_network"] and outputs a summary
    return state

def vulnerability(state: AgentState) -> AgentState:
    return state

def cvss_formatter(state: AgentState) -> AgentState:
    # this will call the XGBoost classifier and then output the vulnerability with its label (None, Low, Medium, High, Critical)
    return state

def reporter(state: AgentState) -> AgentState:
    return state


## --- GRAPH DEFINITION --- ##
workflow = StateGraph(AgentState)
workflow.add_node("recon", recon)
workflow.add_node("recon_analysis", recon_analysis)
workflow.add_node("vulnerability", vulnerability)
workflow.add_node("cvss_formatter", cvss_formatter)
workflow.add_node("supervisor", reporter)

workflow.add_edge("recon", "recon_analysis")
workflow.add_edge("recon_analysis", END)  # TEST EDGE
# workflow.add_edge("recon_analysis", "supervisor")
# workflow.add_edge("recon", "vulnerability")
# workflow.add_edge("vulnerability", "cvss_formatter")
# workflow.add_edge("cvss_formatter", "supervisor")
workflow.set_entry_point("recon")

sam = workflow.compile()

if __name__ == "__main__":
    initial_state = {
        "targets": [],
        "recon_results": {},
        "vuln_results": [],
        "network_findings": ""
    }

    results = sam.invoke(initial_state)
    print(json.dumps(results, indent=2))