# LangChain (v0.3.74)/LangGraph agent using gpt-oss or claude

# libraries
# from langchain.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI  # chatgpt
from langchain_anthropic import ChatAnthropic  # claude
# from langchain.agents import create_react_agent
from toolkit import *
from ..src.xml_to_network import dictionary_to_networkx
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import tool_node
from typing_extensions import TypedDict
import networkx as nx
# from langgraph.checkpoint import MemorySaver

# define schema for the agent
# https://medium.com/ai-agents/langgraph-for-beginners-part-4-stategraph-794004555369
class SAM_State(TypedDict):
    targets: list[str]
    scan_results: dict
    graph_data: nx.graph
    logs: list

def llm_node(state: SAM_State):
    pass

## GRAPH CONSTRUCTION ##
# intialize graph
workflow = StateGraph(SAM_State)

# nodes
ReconNode = tool_node(ping_sweep)
PortScanNode = tool_node(port_scan_stealth)
ServiceEnumNode = tool_node(service_enum)
VulnScanNode = tool_node(vuln_scan)
ReportNode = llm_node("Summarize findings + suggest next steps.")

# workflow
workflow.add_node("recon", ReconNode)
workflow.add_node("portscan", PortScanNode)
workflow.add_node("enum", ServiceEnumNode)
workflow.add_node("vuln", VulnScanNode)
workflow.add_node("report", ReportNode)

# set the starting point for SAM
workflow.set_entry_point("recon")

# add workflow edges
workflow.add_edge()
workflow.add_edge()
workflow.add_edge()
workflow.add_edge()

SAM_Agent = workflow.compile(checkpointer=MemorySaver())


# # define the toolkit 
# tools = [ping_sweep, 
#          port_scan_stealth, 
#          port_scan_stealth, 
#          port_scan_decoy, 
#          port_scan_aggressive, 
#          service_enum, 
#          os_fingerprint, 
#          vuln_scan, 
#          pseudo_exploit]
# llm_w_tools = LLM.bind_tools(tools)

# system_prompt = """
# You are SAM (Security Assessment Machine), an autonomous penetration testing agent. 
# Your role is to conduct network reconnaissance and vulnerability scanning in a structured, methodical way.
 
# Methodology & Rules
# - Follow penetration testing methodology:
#   1. Host discovery (ping sweeps).
#   2. Port scanning (stealth first, decoy if needed, aggressive last).
#   3. Service enumeration (grab banners, versions).
#   4. OS fingerprinting (determine host OS).
#   5. Vulnerability scanning (map services to known vulnerabilities).
#   6. (Optional) Exploitation attempts (simulated).
 
# - Each tool you use corresponds to one stage of this process. 
# - You should choose tools based on the current stage and the results already gathered.
# - Be efficient: DO NOT RERUN THE SAME SCANS AGAINST THE SAME TARGET if results already exist in memory or the database.
# - Always prefer the least noisy / stealthy scan first, escalate to aggressive scans only if necessary.
 
# Memory Hint
# - Before running any tool, check memory/database logs for prior results of that scan type on the same target.
# - If results already exist and are still valid, do not rerun the scan.
# - Instead, reference stored results and continue to the next step.

# Output Expectations
# - Return structured results that can be parsed downstream (XML for scans, plain text for pseudo exploits).
# - Always explain WHY you chose a particular scan in context of the methodology (e.g., "Running stealth port scan after finding host alive via ping sweep").
# - When you encounter an error or timeout, record it in memory and move on logically.
 
# Behavior
# - Think like a penetration tester, not a brute force scanner.
# - Your goal is efficient, accurate, and stealthy reconnaissance.
# - Escalate logically: discovery to enumeration to vulnerability to exploitation.
# - Respect prior knowledge from memory: avoid repeating redundant actions.
 
# You have the following tools available:
# - ping_sweep
# - port_scan_stealth
# - port_scan_decoy
# - port_scan_aggressive
# - service_enum
# - os_fingerprint
# - vuln_scan
# - pseudo_exploit
# """

# # create an Agent instance
# sam = create_react_agent(
#     llm=LLM,
#     tools=tools,
#     prompt=system_prompt
# )

# # create LangGraph of SAM
# """
# 1. takes the goal
# 2. SAM decides sequence of tools to run
# 3. each tool result is parsed
# """
# def run_sam():
#     pass