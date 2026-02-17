from core.state import AgentState
from core.llm import get_llm
from utils.helpers import target_to_proper_file_name
from agents.prompts import OS_FINGERPRINT_SYSTEM_PROMPT
from config.logging_config import get_logger

import json
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# call global log file
logger = get_logger(__name__)

def os_analysis(state: AgentState) -> AgentState:
    """
    MAKE DOCSTRING
    """
    logger.info("OS analysis started")

    # define variables agent will use
    os_results = state.get("os_fingerprint_results", {})
    discovered_hosts = state.get("recon_results", {}).get("discovered_hosts", [])   
    logger.debug(f"There are {len(discovered_hosts)} hosts discovered -> {discovered_hosts}")

    os_analysis_prompt = f"""
    Analyze the following OS fingerprinting results and provide a structured summary.
    
    OS Fingerprinting Data:
    {json.dumps(os_results, indent=2)}
    
    Discovered Hosts:
    {json.dumps(discovered_hosts, indent=2)}
    
    Instructions:
    1. Summarize the OS landscape of the network
    2. Identify the most common operating systems
    3. Highlight any unusual or outdated OS versions
    4. Note any hosts where OS detection failed or has low confidence
    5. Identify potential targets for vulnerability scanning based on OS
    
    Output a concise technical summary in markdown format.
    """
    llm = get_llm()
    os_analysis = llm.invoke([
        SystemMessage(content=OS_FINGERPRINT_SYSTEM_PROMPT),
        HumanMessage(content=os_analysis_prompt)
    ])
    
    # store the analysis
    os_analysis = AIMessage(os_analysis) if not isinstance(os_analysis, AIMessage) else os_analysis
    state["os_analysis"] = os_analysis.content
    
    # write OS analysis to file
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./output/{target_ip}_os_fingerprinting.txt", "w", encoding="utf-8") as f:
        f.write("=== OS FINGERPRINTING RESULTS ===\n\n")
        f.write(os_analysis.content)
        f.write("\n\n=== RAW OS DATA ===\n\n")
        f.write(json.dumps(os_results, indent=2))
    
    logger.debug(f"OS analysis completed. Found OS data for {len(os_results)} hosts.")
    
    return state
