# LangChain (v0.3.74)/LangGraph agent using gpt-oss or claude

# libraries
from langchain.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI  # chatgpt
from langchain_anthropic import ChatAnthropic  # claude
from langchain.agents import create_react_agent
from toolkit import *
from ..src.xml_to_network import dictionary_to_networkx
from langgraph.graph import StateGraph

# define LLM
LLM = ChatOpenAI(model="", api_key="")

# define memory
memory = ConversationBufferMemory(memory_key="history", return_messages=True)

# define the toolkit 
tools = [ping_sweep, 
         port_scan_stealth, 
         port_scan_stealth, 
         port_scan_decoy, 
         port_scan_aggressive, 
         service_enum, 
         os_fingerprint, 
         vuln_scan, 
         pseudo_exploit]
llm_w_tools = LLM.bind_tools(tools)

system_prompt = """"""

# create an Agent instance
sam = create_react_agent(
    llm=LLM,
    tools=tools,
    prompt=system_prompt
)

# create LangGraph of SAM
"""
1. takes the goal
2. SAM decides sequence of tools to run
3. each tool result is parsed
"""
def run_sam():
    pass