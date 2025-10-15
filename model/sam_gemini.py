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
import datetime

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
RECON_SYSTEM_PROMPT = """
You are an autonomous network reconnaissance agent. 
Your ONLY task is to decide the next network scan operation. 
You must ALWAYS respond in **pure JSON**.

### REQUIRED OUTPUT FORMAT
{
  "flags": [string],
  "targets": [string],
  "scan_type": "low" | "medium" | "high",
  "reason": "string",
  "max_runtime_s": int
}

### RULES
1. No markdown, no code blocks, no explanations.
2. Do not include backticks, comments, or text outside the JSON.
3. If uncertain, use defaults:
   - flags: []
   - targets: from the input["targets"]
   - scan_type: "low"
   - reason: "default safe scan"
   - max_runtime_s: 30
4. Always return exactly one JSON object.
"""


RECON_ANALYSIS_SYSTEM_PROMPT = """"""

## --- AGENT TOOL BINDING --- ##
# recon_llm = llm.bind_tools([], system_prompt=RECON_SYSTEM_PROMPT, return_direct=True)  # return_direct tells the tool binding to return the AI's raw output


## --- AGENT DEFINITIONS --- ##
def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

    # Load previous recon state if exists
    prev = state.get("recon_results", {})
    if prev:
        parsed = prev.get("parsed_network", {})
        discovered_hosts.update(parsed.keys())

    # --- RECON LOOP ---
    while iteration < max_iterations and no_new_count < no_new_threshold:
        iteration += 1

        print(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")

        # Simplified LLM input
        llm_input = f"""
        You are an autonomous network reconnaissance specialist.

        Context summary:
        - Known hosts discovered so far: {len(discovered_hosts)}.
        - Total scan iterations completed: {len(aggregated_logs)}.
        - Active targets under analysis: {', '.join(state['targets'])}.

        If no new hosts or open ports have been found after 2 iterations, 
        switch to a **different scanning strategy** automatically. 
        You may adjust parameters such as:
        - Port range (`-p`), e.g. limit to 1–1024 or top 1000 ports
        - Timing template (`-T`), e.g. T3 for normal or T5 for fast scans
        - Discovery methods (`-sn`, `-Pn`, `-sS`, `-sU`)
        - Parallelism and retries (`--max-retries`, `--min-rate`, etc.)

        Your goal is to produce a JSON decision that adapts dynamically 
        to scan results and previous outcomes.

        Respond **only** with valid JSON in this exact schema:
        {{
        "flags": [string],          # example: ["-T4", "-sS", "--open"]
        "targets": [string],        # subnets or hosts to focus on
        "scan_type": "low" | "medium" | "high",
        "reason": "string",         # describe why the new strategy is chosen
        "max_runtime_s": int        # upper bound for how long this scan can run
        }}
        """


        # --- STEP 1: Ask Gemini for the next scan decision ---
        raw_decision: AIMessage = llm.invoke(
            llm_input,
            system_message=SystemMessage(content=RECON_SYSTEM_PROMPT),
            return_direct=True
        )

        raw_text = getattr(raw_decision, "content", str(raw_decision))
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")

        # --- STEP 2: Try to extract JSON ---
        decision = extract_json(raw_text, iteration)

        # --- STEP 3: Auto-repair fallback if JSON not found ---
        if not decision:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ⚠️ No valid JSON, reprompting model to reformat output...")

            repair_prompt = f"""
                                Reformat the following text into a valid JSON object that matches:
                                {{
                                "flags": [],
                                "targets": [],
                                "scan_type": "low",
                                "reason": "string",
                                "max_runtime_s": 30
                                }}

                                Text to fix:
                                {raw_text}
                            """

            repaired = llm.invoke(
                repair_prompt,
                system_message=SystemMessage(content=RECON_SYSTEM_PROMPT),
                return_direct=True
            )

            decision = extract_json(getattr(repaired, "content", str(repaired)), iteration)

            if not decision:
                # Still invalid — log and skip iteration
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

        # --- STEP 4: Validate decision fields ---
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

        # --- STEP 5: Run validated nmap scan ---
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running Nmap scan: {dec_targets}")
        log = nmap_scanning.invoke({
            "scan_type": decision.get("scan_type", state["scan_type"]),
            "flags": flags,
            "targets": dec_targets,
            "timeout": min(max_runtime, TIMEOUT_VAL)
        })
        aggregated_logs.append(log)

        # --- STEP 6: Parse scan output ---
        parsed = {}
        if log.get("xml"):
            parsed = xml_parse(log["xml"])

        # --- STEP 7: Detect new hosts ---
        hosts = set(parsed.keys()) - discovered_hosts
        if hosts:
            print(f"✅ New hosts discovered: {hosts}")
            discovered_hosts.update(hosts)
            no_new_count = 0
        else:
            print("~No new hosts found.")
            no_new_count += 1

        # --- STEP 8: Update agent state ---
        state["recon_results"] = {
            "last_log": log,
            "parsed_network": parsed,
            "all_logs": aggregated_logs,
            "discovered_hosts": list(discovered_hosts),
            "iteration": iteration
        }

        print(f"📊 Hosts discovered so far: {state['recon_results']['discovered_hosts']}")
        time.sleep(1)

    print(f"🧭 Recon finished after {iteration} iterations.")
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
        "scan_type": "high",
        "targets": ["10.10.162.0/24"],  # whole subnet scan
        "recon_results": {},
        "vuln_results": [],
        "network_findings": ""
    }

    results = sam.invoke(initial_state)
    print(json.dumps(results, indent=2))