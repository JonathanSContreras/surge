"""
@author: Brianna Hinds
Description: Agentic System Build
"""

## --- LIBRARIES --- ##
import os
from dotenv import load_dotenv

# Agentic libraries
from typing import TypedDict
from langchain_google_genai import GoogleGenerativeAI
from langgraph.graph import StateGraph, END

# tools
from tools import nmap_scanning


## --- LLM DEFINTION --- ##
load_dotenv()
API = os.getenv("GOOGLE_API_KEY")
llm = GoogleGenerativeAI(
    model="",
    google_api_key=API,
    temperature=0
)

## --- AGENTSTATE --- ##
class AgentState(TypedDict):
    # targets: list[str]
    recon_results: str
    vuln_results: list[str]  # list of CVE vulnerabilities and its score
    final_report: str

## --- AGENT PROMPTS --- ##
RECON_SYSTEM_PROMPT = """"""

## --- AGENT TOOL BINDING --- ##
recon_llm = llm.bind_tools()


## --- AGENT DEFINITIONS --- ##
def recon(state: AgentState) -> AgentState:
    """"""

    response = llm.
    return state

def recon_analysis(state: AgentState) -> AgentState:
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

    }

    results = sam.invoke(initial_state)