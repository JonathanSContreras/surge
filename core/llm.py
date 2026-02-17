import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from config.constants import MODEL_CONFIG

load_dotenv()
BASE_URL = os.getenv("TAILSCALE_URL")

def get_llm():
    """
    Central LLM factory.
    Allows environment-based configuration.
    """
    return ChatOpenAI(
        base_url=BASE_URL,
        model=MODEL_CONFIG["model_name"],
        api_key="ollama",  # unused placeholder value
        temperature=MODEL_CONFIG["temperature"],
        top_p=MODEL_CONFIG["determinism"]
        # timeout=MODEL_CONFIG["timeout"],
    )
