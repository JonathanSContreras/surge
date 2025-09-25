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
from langchain.schema import AIMessage, SystemMessage

# tools
from tools import nmap_scanning, xml_parse

# other imports
from globals import TIMEOUT_VAL
from helper import extract_json
import json
import time

## --- LLM DEFINTION --- ##
load_dotenv()
API = os.getenv("GOOGLE_API_TOKEN")
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=API,
    temperature=0
)

## --- AGENTSTATE --- ##
class AgentState(TypedDict):
    scan_type: str  # e.g. "low"/"medium"/"high"
    targets: list[str]  # e.g. ["10.10.1/25"]
    recon_results: dict[str, Any]  # the output would be a json, raw_xml, scan_logs, etc
    vuln_results: list[str]  # list of CVE vulnerabilities and its score
    network_findings: str

## --- AGENT PROMPTS --- ##
RECON_SYSTEM_PROMPT =  """
You are an autonomous network reconnaissance agent with authorized access to the target IP range. Your goal is to fully discover hosts, services, and open ports.

You must respond **only** with JSON. The JSON must always contain all fields and be valid. Example:

{
  "flags": [],
  "targets": [],
  "scan_type": "low",
  "reason": "brief explanation",
  "max_runtime_s": 30
}

Rules:
1. Do NOT include explanations, markdown, or text. JSON only.
2. Always include all keys exactly as shown.
3. `flags` and `targets` must be lists (empty lists are valid).
4. `scan_type` must be "low", "medium", or "high".
5. `max_runtime_s` must be an integer.
6. `reason` must be a string.

If you cannot determine a value, use safe defaults: empty lists, "low", 30 seconds.
"""
RECON_ANALYSIS_SYSTEM_PROMPT = """"""

## --- AGENT TOOL BINDING --- ##
# recon_llm = llm.bind_tools([], system_prompt=RECON_SYSTEM_PROMPT, return_direct=True)  # return_direct tells the tool binding to return the AI's raw output


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
    aggregated_logs = []

    # set condition variables so the model doesn't get stuck
    no_new_count = 0
    no_new_threshold = 2

    # use previous recon results
    prev = state.get("recon_results", {})
    if prev:
        parsed = prev.get("parsed_network", {})
        discovered_hosts.update(parsed.keys())
    
    # define a stop condition for the looping
    while iteration < max_iterations and no_new_count < no_new_threshold:
        iteration += 1

        # prompt content
        llm_input = {
            "known_hosts": list(discovered_hosts)[:200],  # cap the size of hosts discovered
            "scan_history": [l.get("command") for l in aggregated_logs[- 5:]],
            "targets": state["targets"]
        }

        ## SANITY CHECK
        print(f"\n--- ITERATION {iteration} ---")
        print(f"LLM input: {json.dumps(llm_input, indent=2)}")
        ####

        # call LLM for next scan JSON
        raw_decision: AIMessage = llm.invoke(
            json.dumps(llm_input), 
            system_message=SystemMessage(content=RECON_SYSTEM_PROMPT), 
            return_direct=True
        )

        # parse the AIMessage
        raw_text = getattr(raw_decision, "content", str(raw_decision))
        print(f"LLM raw output: {raw_text}")

        # extract the JSON
        decision = extract_json(raw_text, iteration)

        if not decision:
            # log error and continue
            aggregated_logs.append({
                "error": "~NO VALID JSON FROM LLM",
                "raw_output": raw_text,
                "iteration": iteration
            })
            no_new_count += 1

            # update the state
            state["recon_results"] = {
                "last_log": {},
                "parsed_network": {},
                "all_logs": aggregated_logs,
                "discovered_hosts": list(discovered_hosts),
                "iteration": iteration
            }
            continue


        # # parse the AIMessage
        # if hasattr(raw_decision, "content"):
        #     raw_text = raw_decision.content
        # else:
        #     raw_text = str(raw_decision)

        # # Extract JSON with fallback
        # decision = extract_json(raw_text, iteration)

        # if not decision:
        #     # If no decision, log & retry (instead of breaking)
        #     aggregated_logs.append({
        #         "error": "No valid JSON from LLM",
        #         "raw_output": raw_text,
        #         "iteration": iteration
        #     })
        #     no_new_count += 1
        #     continue  # skip this round but keep recon loop alive

        # parse the AIMessage
        # if hasattr(raw_decision, "content"):
        #     raw_text = raw_decision.content
        # else:
        #     raw_text = str(raw_decision)

        # # extract JSON using regex
        # match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        # if match:
        #     decision = json.loads(match.group(0))
        # else:
        #     decision = {}

        # validate decision
        flags = decision.get("flags", [])
        dec_targets = decision.get("targets", [])
        max_runtime = decision.get("max_runtime_s", TIMEOUT_VAL)

        ## --- SANITY CHECKS --- ##
        # check nmap scanning parameters
        if not isinstance(flags, list) or not isinstance(dec_targets, list):
            print(f"~INVALID DECISION FIELDS:\tflags: {flags}\ttargets: {dec_targets}")
            no_new_count += 1
            continue
        
        
        if len(dec_targets) == 0:
            print("~LLM DEFINED NO TARGETS")
            no_new_count += 1
            continue
        ####

        # run the validated nmap
        log = nmap_scanning.invoke({
            "scan_type": decision.get("scan_type", state["scan_type"]), 
            "flags": flags, 
            "targets": dec_targets, 
            "timeout": min(max_runtime, TIMEOUT_VAL)})
        aggregated_logs.append(log)

        # parse xml
        parsed = {}
        if log.get("xml"):
            parsed = xml_parse(log["xml"])  # this can take either an xml file or a string

        # detect new hosts
        hosts = set(parsed.keys()) - discovered_hosts
        if hosts:
            discovered_hosts.update(hosts)
            no_new_count = 0
        else: # nothing new was found
            no_new_count += 1

        # update state
        state["recon_results"] = {
            "last_log": log if decision else {},
            "parsed_network": parsed if decision else {},
            "all_logs": aggregated_logs,
            "discovered_hosts": list(discovered_hosts),
            "iteration": iteration
        }

        print(f"Discovered hosts so far: {state['recon_results']['discovered_hosts']}")

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
        "scan_type": "low",
        "targets": ["10.10.160.0/22"],
        "recon_results": {},
        "vuln_results": [],
        "network_findings": ""
    }

    results = sam.invoke(initial_state)
    print(json.dumps(results, indent=2))