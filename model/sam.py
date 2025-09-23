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
    pass

## --- AGENT PROMPTS --- ##


## --- AGENT DEFINITIONS --- ##