from core.state import AgentState
from config.constants import SCANNING_DUMP_LOG, TIMEOUT_VAL
from utils.helpers import _now
from execution.nmap_scanner import nmap_scanning
from execution.xml_parser import xml_parse
from config.logging_config import get_logger

# call global log file
logger = get_logger(__name__)

# max hosts per nmap call — keeps each scan within the timeout budget
OS_SCAN_BATCH_SIZE = 10


def os_fingerprint_finder(state: AgentState) -> AgentState:
    """
    Performs an aggressive OS fingerprinting on all discovered hosts.

    This agent takes the list of discovered hosts from reconnaissance, and runs a targeted nmap OS detection scan,
    and extractes detailed operating system information including:
    - OS family and version
    - accuracy/confidence scores
    - CPE identifiers for vulnerability correlation
    - TCP/IP stack fingerprints
    Returns the updated AgentState with os_fingerprint_results containing structured OS data.

    ARGS
        state: passed AgentState, current pipeline state with discovered hosts from recon
    """
    # extracted discovered hosts from recon results
    discovered_hosts = state.get("recon_results", {}).get("discovered_hosts", [])

    if not discovered_hosts:
        logger.info("No hosts discovered in recon phase, skipping OS fingerprinting.")
        state["os_fingerprint_results"] = {}
        return state

    logger.info(f"Starting OS fingerprinting for {len(discovered_hosts)} hosts...")

    os_scan_flags = [
        "-sS",
        "-sV",
        "-O",
        "--osscan-guess",
        "--max-retries", "4",
        "--reason",
        "-Pn"
    ]

    # split hosts into batches so no single nmap call exceeds the timeout budget
    batches = [
        discovered_hosts[i:i + OS_SCAN_BATCH_SIZE]
        for i in range(0, len(discovered_hosts), OS_SCAN_BATCH_SIZE)
    ]
    total_batches = len(batches)
    logger.info(f"Splitting {len(discovered_hosts)} hosts into {total_batches} batch(es) of up to {OS_SCAN_BATCH_SIZE}")

    os_results = {}
    last_log = {}

    for batch_num, batch in enumerate(batches, start=1):
        logger.info(f"OS scan batch {batch_num}/{total_batches}: {batch}")
        os_scan_log = nmap_scanning.invoke({
            "scan_type": "high",
            "flags": os_scan_flags,
            "targets": batch,
            "timeout": TIMEOUT_VAL
        })
        last_log = os_scan_log

        # write to scan log dump
        with open(SCANNING_DUMP_LOG, "a") as f:
            f.write(f"\n\n [OS FINGERPRINTING SCAN - batch {batch_num}/{total_batches}] [{_now()}]")
            f.write(f"\nTargets: {batch}")
            f.write(f"\nFlags: {os_scan_flags}")
            f.write(f"\nSuccess: {os_scan_log.get('success')}\n")

        if not os_scan_log.get("success") or not os_scan_log.get("xml_file"):
            logger.warning(f"Batch {batch_num}/{total_batches} failed or returned no XML — skipping")
            continue

        xml_path = f"{os_scan_log['xml_dir']}/{os_scan_log['xml_file']}"
        logger.info(f"Parsing XML for batch {batch_num}: {xml_path}")

        parsed_data = xml_parse(xml_path)

        for host_ip, host_data in parsed_data.items():
            os_info = host_data.get("os", {})
            os_results[host_ip] = {
                "os_matches": os_info.get("matches", []),
                "os_classes": os_info.get("classes", []),
                "fingerprint": os_info.get("fingerprint", ""),
                "ports_used": os_info.get("ports_used", []),
                "accuracy": os_info.get("accuracy", 0),
                "cpe": os_info.get("cpe", []),
                "device_type": os_info.get("device_type", "unknown"),
                "vendor": os_info.get("vendor", "unknown")
            }

        # store XML content from last successful batch
        with open(xml_path, "r", encoding="utf-8") as f:
            state["os_xml_content"] = f.read()

    logger.info(f"OS fingerprinting complete: {len(os_results)}/{len(discovered_hosts)} hosts returned OS data")

    state["os_fingerprint_results"] = os_results
    return state