import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from config.constants import MODEL_CONFIG, ANALYSIS_MODEL_CONFIG, OPENROUTER_BASE_URL

load_dotenv()
BASE_URL = os.getenv("TAILSCALE_URL")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

USE_ONLINE = os.getenv("USE_ONLINE", "0") == "1"

def get_llm(tier: str = "fast"):
    """
    Central LLM factory.

    tier="fast"     → local gpt_oss:20b via Tailscale/Ollama (structured tasks, tool calling)
    tier="analysis" → OpenRouter (heavy reasoning, synthesis, report generation)

    Set USE_ONLINE=1 in .env to route ALL tiers through OpenRouter (for testing).
    """
    if tier == "analysis" or USE_ONLINE:
        model = ANALYSIS_MODEL_CONFIG["model_name"]
        return ChatOpenAI(
            base_url=OPENROUTER_BASE_URL,
            model=model,
            api_key=OPENROUTER_API_KEY,
            temperature=ANALYSIS_MODEL_CONFIG["temperature"],
        )
    return ChatOpenAI(
        base_url=BASE_URL,
        model=MODEL_CONFIG["model_name"],
        api_key="ollama",
        temperature=MODEL_CONFIG["temperature"],
        top_p=MODEL_CONFIG["determinism"],
    )
