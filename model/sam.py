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

# SYSTEM_PROMPT = 

# define schema for the agent
# https://medium.com/ai-agents/langgraph-for-beginners-part-4-stategraph-794004555369
class SAM_State(TypedDict):
    targets: list[str]
    scan_results: dict
    graph_data: nx.graph
    logs: list

def llm_node(state: SAM_State):
    # summarize findings
    model = ChatOpenAI(model="", api="")  # or use claude
    response = model.invoke(f"Summaroze scan results: {str(state["scan_results"])}")
    state["logs"].append(response)
    return state

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
workflow.add_edge("recon", "portscan")
workflow.add_edge("portscan", "enum")
workflow.add_edge("enum", "vuln")
workflow.add_edge("vuln", "report")

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
