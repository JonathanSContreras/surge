from langgraph.graph import StateGraph, END
from core.state import AgentState

# import agent entry functions
from agents.recon_agent import recon
from agents.recon_analysis import recon_analysis
from agents.os_fingerprint_agent import os_fingerprint_finder
from agents.os_analysis import os_analysis
from agents.vuln_agent import vulnerability
from agents.data_formatting_agent import cvss_data_formatter
from agents.cvss_scoring import cvss_scoring
from agents.reporter import reporter

def build_mas_graph():
    """
    Graph outline for the MAS.
    """
    # initialize graph
    workflow = StateGraph(AgentState)

    # define agents (1 node = 1 agent)
    workflow.add_node("recon", recon)
    workflow.add_node("recon_analyzer", recon_analysis)
    workflow.add_node("os_finder", os_fingerprint_finder)
    workflow.add_node("os_analyzer", os_analysis)
    workflow.add_node("vulnerability", vulnerability)
    workflow.add_node("cvss_data_formatter", cvss_data_formatter) 
    workflow.add_node("cvss_scoring", cvss_scoring) 
    workflow.add_node("reporter", reporter)
    
    # define workflow entry point
    workflow.set_entry_point("recon")

    # define each edge
    workflow.add_edge("recon", "recon_analyzer")
    workflow.add_edge("recon_analyzer", "os_finder")
    workflow.add_edge("os_finder", "os_analyzer")
    workflow.add_edge("os_analyzer", "vulnerability")
    workflow.add_edge("vulnerability", "cvss_data_formatter")
    workflow.add_edge("cvss_data_formatter", "cvss_scoring")
    workflow.add_edge("cvss_scoring", "reporter")
    workflow.add_edge("reporter", END)

    return workflow.compile()

