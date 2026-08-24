import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from config.constants import (
    MODEL_CONFIG, ANALYSIS_MODEL_CONFIG, FAST_ONLINE_MODEL_CONFIG, OPENROUTER_BASE_URL,
)

load_dotenv()
BASE_URL = os.getenv("TAILSCALE_URL")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")


def get_llm(tier: str = "fast"):
    """
    Central LLM factory. Reads runtime model config on every call so Settings
    changes take effect without a server restart.

    mode="offline"  → everything local via Ollama. This is the fallback when the
                      OpenRouter credits run dry; it must NOT reach out to
                      OpenRouter for any tier, or the fallback is useless.
    mode="online"   → OpenRouter, but split by tier so the cheap structured work
                      isn't billed at the analysis model's rate:
                        tier="fast"     → online_fast_model  (recon_agent,
                                          data_formatting_agent — JSON emission)
                        tier="analysis" → online_model       (recon_analysis,
                                          os_analysis, vuln_agent, reporter)
    """
    from api.routes.settings import _model_settings  # deferred to avoid circular import at load time

    # --- offline: fully local, no OpenRouter call for any tier ---
    if _model_settings["mode"] == "offline":
        return ChatOpenAI(
            base_url=_model_settings["offline_base_url"] or BASE_URL,
            model=_model_settings["offline_model"] or MODEL_CONFIG["model_name"],
            api_key="ollama",
            temperature=MODEL_CONFIG["temperature"],
            top_p=MODEL_CONFIG["determinism"],
            timeout=MODEL_CONFIG["timeout"],
        )

    # --- online: OpenRouter, different model per tier ---
    if tier == "analysis":
        return ChatOpenAI(
            base_url=OPENROUTER_BASE_URL,
            model=_model_settings["online_model"] or ANALYSIS_MODEL_CONFIG["model_name"],
            api_key=OPENROUTER_API_KEY,
            temperature=ANALYSIS_MODEL_CONFIG["temperature"],
            timeout=ANALYSIS_MODEL_CONFIG["timeout"],
            max_retries=3,
        )

    return ChatOpenAI(
        base_url=OPENROUTER_BASE_URL,
        model=_model_settings["online_fast_model"] or FAST_ONLINE_MODEL_CONFIG["model_name"],
        api_key=OPENROUTER_API_KEY,
        temperature=FAST_ONLINE_MODEL_CONFIG["temperature"],
        timeout=FAST_ONLINE_MODEL_CONFIG["timeout"],
        max_retries=3,
    )
