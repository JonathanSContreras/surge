from core.state import AgentState
from core.llm import get_llm
from agents.prompts import RECON_ANALYSIS_SYSTEM_PROMPT
from utils.helpers import target_to_proper_file_name
from config.logging_config import get_logger

from langchain.schema import AIMessage, SystemMessage, HumanMessage
import json

# call global log file
logger = get_logger(__name__)

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
    logger.info("Recon analysis agent started")

    # define what things the analysis agent will need to give for a full analysis
    recon_results = state["recon_results"]
    all_logs = recon_results.get("all_logs", [])
    xml_content = recon_results.get("all_xml_content", "")

    # # read text file and put in logs variable
    # with open(SCANNING_DUMP_LOG, "r") as log_file:
    #     logs = log_file.read()

    # all xml output (already outputted in a file)
    # xml_file = state["all_xml_content"]

    # print(xml_file)
    # print(logs)

    # define the agent's prompt
    analysis_prompt = f"""
    You are a network reconnaissance analyst.

    Below are the inputs for your analysis:
    -------------------------
    RECON SCAN LOG CONTENT:
    {all_logs}

    PARSED NETWORK MAP (from Nmap XML concatentation):
    {xml_content}

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
    llm = get_llm()
    result = llm.invoke([
        SystemMessage(content=RECON_ANALYSIS_SYSTEM_PROMPT),
        HumanMessage(content=analysis_prompt)
    ])

    # check if result answer is a string
    result = AIMessage(result) if not isinstance(result, AIMessage) else result
    state["recon_analysis"] = result.content

    # write the analysis into a txt file
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./report/{target_ip}_recon_analysis.txt", "w", encoding="utf-8") as f:
        f.write(result.content)

    # print(state["recon_analysis"])

    logger.info("Recon analysis agent finished analysis and updated the state.")

    return state