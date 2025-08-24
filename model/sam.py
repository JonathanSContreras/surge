# LangChain (v0.3.74)/LangGraph agent using gpt-oss or claude

# libraries
from typing_extensions import TypedDict
import networkx as nx
from langchain_openai import ChatOpenAI  # chatgpt
from langchain_anthropic import ChatAnthropic  # claude
from langgraph.prebuilt import tool_node
from toolkit import *
from ..src.xml_to_network import dictionary_to_networkx
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

# define state schema
# https://medium.com/ai-agents/langgraph-for-beginners-part-4-stategraph-794004555369
class SAM_State(TypedDict):
    target: list[str]  # list of IPs/subnets
    scan_results: dict
    graph_data: nx.graph
    logs: list[str]
    next_action: str  # chosen by LLM

# llm setup
llm = ChatOpenAI(model="")  # or claude

# define the tools from the toolkit and other tools as well
ReconNode = tool_node(ping_sweep)
PortScanAggressive= tool_node(port_scan_aggressive)
PortScanDecoy = tool_node(port_scan_decoy)
PortScanStealth = tool_node(port_scan_stealth)
EnumNode = tool_node(service_enum)
OsNode = tool_node(os_fingerprint)
VulnNode = tool_node(vuln_scan)
ClassifierNode = tool_node() # call the vulnerability classifier
ExploitNode = tool_node(pseudo_exploit)
ReportNode = tool_node()  # make a generate_report tool

# llm planner node 
def planner_node(state: SAM_State) -> SAM_State:
    """
    Ask the LLM what to do based on the results it was given.
    """
    context = "\n".join(state["logs"])
    findings = state["scan_results"]

    prompt = f"""
    You are SAM (Security Assessment Machine), an autonomous penetration testing agent. 
    Your role is to conduct network reconnaissance and vulnerability scanning in a structured, methodical way.

    Context so far:
    {context}

    Findings:
    {findings}

    Decide the **next best action**:
    Options:
      - recon
      - portscan_stealth
      - portscan_decoy
      - portscan_aggressive
      - enum
      - os_scan
      - vuln_scan
      - vuln_classifier
      - exploit
      - report

    Respond with one action only.
    """

    decision = llm.invoke(prompt).content.strip().lower()

    # if the LLM output is outside the scope, then run a report
    if decision not in ["recon", "portscan_stealth", "portscan_aggressive", "portscan_decoy", "enum", "vuln_scan", "vuln_classifier", "exploit", "report", "os_scan"]:
        decision = "report"

    state["next_action"] = decision
    state["logs"].append(f"SAM decided: {decision}")
    return state

## WORKFLOW CONSTRUCTION
workflow = StateGraph(SAM_State)

# add planner node
workflow.add_node("planner", planner_node)

# add all tool nodes
workflow.add_node("recon", ReconNode)
workflow.add_node("portscan_decoy", PortScanDecoy)
workflow.add_node("portscan_aggresive", PortScanAggressive)
workflow.add_node("portscan_stealth", PortScanStealth)
workflow.add_node("os_scan", OsNode)
workflow.add_node("enum", EnumNode)
workflow.add_node("vuln_scan", VulnNode)
workflow.add_node("vuln_classifier", ClassifierNode)
workflow.add_node("exploit", ExploitNode)
workflow.add_node("report", ReportNode)

# start at recon
workflow.set_entry_point("recon")

# Edges: after ANY tool → planner
for node in [
    "recon", "portscan_stealth", "portscan_decoy", "portscan_aggressive",
    "enum", "vuln_scan", "vuln_classifier", "exploit", "os_scan"
]:
    workflow.add_edge(node, "planner")

# Planner routes dynamically to chosen next action
for choice in [
    "recon", "portscan_stealth", "portscan_decoy", "portscan_aggressive",
    "enum", "vuln_scan", "vuln_classifier", "exploit", "report", "os_scan"
]:
    workflow.add_conditional_edges(
        "planner",
        lambda state: state["next_action"],
        {choice: choice}
    )

SAM_Agent = workflow.compile(checkpointer=MemorySaver())