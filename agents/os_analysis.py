from core.state import AgentState
from core.llm import get_llm
from utils.helpers import target_to_proper_file_name
from agents.prompts import OS_FINGERPRINT_SYSTEM_PROMPT
from config.logging_config import get_logger

import json
from langchain.schema import AIMessage, SystemMessage, HumanMessage

# call global log file
logger = get_logger(__name__)

# FIX 3: max hosts per LLM batch — keeps each call well under the 131K context limit
BATCH_SIZE = 8


def _slim_os_results(os_results: dict) -> dict:
    """
    FIX 1: Strips fields that are too large or useless for LLM analysis:
    - 'fingerprint': raw TCP/IP probe strings, not useful to the LLM
    - 'os_classes': redundant with os_matches
    - 'ports_used': low-value for OS summary analysis
    Keeps top 3 os_matches and top 5 CPEs.
    """
    slimmed = {}
    for host, data in os_results.items():
        slimmed[host] = {
            "accuracy": data.get("accuracy", 0),
            "device_type": data.get("device_type"),
            "vendor": data.get("vendor"),
            "os_matches": data.get("os_matches", [])[:3],
            "cpe": data.get("cpe", [])[:5],
        }
    return slimmed


def _chunk(data: dict, size: int) -> list[dict]:
    """Split a dict into a list of smaller dicts of at most `size` keys."""
    items = list(data.items())
    return [dict(items[i:i + size]) for i in range(0, len(items), size)]


def _analyze_batch(llm, batch: dict, batch_num: int, total_batches: int) -> str:
    """Run a single LLM analysis call for one batch of hosts."""
    prompt = f"""
    Analyze the following OS fingerprinting results for a subset of hosts ({batch_num}/{total_batches}).

    OS Fingerprinting Data:
    {json.dumps(batch)}

    Instructions:
    1. Summarize the OS landscape for these hosts
    2. Highlight any unusual or outdated OS versions
    3. Note hosts where OS detection failed (accuracy: 0)
    4. Identify potential targets for vulnerability scanning

    Output a concise technical summary in markdown format.
    """
    response = llm.invoke([
        SystemMessage(content=OS_FINGERPRINT_SYSTEM_PROMPT),
        HumanMessage(content=prompt)
    ])
    return response.content if hasattr(response, "content") else str(response)


def _aggregate_batch_analyses(llm, batch_summaries: list[str]) -> str:
    """Merge per-batch summaries into a single cohesive final analysis."""
    combined = "\n\n---\n\n".join(
        f"### Batch {i + 1}\n{s}" for i, s in enumerate(batch_summaries)
    )
    prompt = f"""
    The following are OS analysis summaries from separate batches of hosts on the same network.
    Merge them into a single cohesive report covering the full network.

    {combined}

    Output a final unified technical summary in markdown format covering:
    1. Overall OS landscape
    2. Most common operating systems
    3. Critical/unusual findings
    4. Hosts where OS detection failed
    5. Recommended targets for vulnerability scanning
    """
    response = llm.invoke([
        SystemMessage(content=OS_FINGERPRINT_SYSTEM_PROMPT),
        HumanMessage(content=prompt)
    ])
    return response.content if hasattr(response, "content") else str(response)


def os_analysis(state: AgentState) -> AgentState:
    """
    Analyzes OS fingerprinting results from the OS fingerprint agent.
    Slims the payload (Fix 1) and batches hosts (Fix 3) to stay within
    the model's 131K context window.
    """
    logger.info("OS analysis started")

    os_results = state.get("os_fingerprint_results", {})
    discovered_hosts = state.get("recon_results", {}).get("discovered_hosts", [])
    logger.debug(f"There are {len(discovered_hosts)} hosts discovered -> {discovered_hosts}")

    # FIX 1: strip bloated fields before sending to LLM
    slimmed = _slim_os_results(os_results)
    logger.debug(f"Slimmed OS results for {len(slimmed)} hosts (removed fingerprint/os_classes/ports_used)")

    llm = get_llm()

    # FIX 3: batch if host count exceeds BATCH_SIZE, otherwise single call
    batches = _chunk(slimmed, BATCH_SIZE)
    total_batches = len(batches)
    logger.info(f"OS analysis: {len(slimmed)} hosts split into {total_batches} batch(es) of up to {BATCH_SIZE}")

    if total_batches == 1:
        final_analysis = _analyze_batch(llm, batches[0], 1, 1)
    else:
        batch_summaries = []
        for i, batch in enumerate(batches, start=1):
            logger.info(f"Analyzing batch {i}/{total_batches} ({len(batch)} hosts)")
            summary = _analyze_batch(llm, batch, i, total_batches)
            batch_summaries.append(summary)
            logger.debug(f"Batch {i}/{total_batches} complete")

        logger.info("Aggregating batch analyses into final summary")
        final_analysis = _aggregate_batch_analyses(llm, batch_summaries)

    state["os_analysis"] = final_analysis

    # write OS analysis to file (full raw data preserved here)
    target_ip = target_to_proper_file_name(state["targets"])
    with open(f"./output/{target_ip}_os_fingerprinting.txt", "w", encoding="utf-8") as f:
        f.write("=== OS FINGERPRINTING RESULTS ===\n\n")
        f.write(final_analysis)
        f.write("\n\n=== RAW OS DATA ===\n\n")
        f.write(json.dumps(os_results, indent=2))

    logger.info(f"OS analysis completed for {len(os_results)} hosts across {total_batches} batch(es).")
    return state
