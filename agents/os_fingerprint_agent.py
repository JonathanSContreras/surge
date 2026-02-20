from core.state import AgentState
from config.constants import SCANNING_DUMP_LOG, TIMEOUT_VAL
from utils.helpers import _now
from execution.nmap_scanner import nmap_scanning
from execution.xml_parser import xml_parse
from config.logging_config import get_logger

# call global log file
logger = get_logger(__name__)

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

    # prepare the OS detection flags
    """
    -O -> enable OS detection
    -A -> aggressive scan
    --osscan-guess -> guess the OS more aggressively
    -Pn -> skip host discovery
    --script=banner -> grab the service banners for more context
    """
    # os_scan_flags = [
    #     "-O",
    #     "-A",
    #     "--osscan-guess",
    #     "-Pn",
    #     "--script=banner,os-fingerprint"
    # ]
    # POSSIBLE FIX    
    os_scan_flags = [
        "-sS",
        "-sV",
        "-O",
        "--osscan-guess",
        "--max-retries", "4",
        "--reason",
        "-Pn"
    ]

    # run a single OS detection scan against all hosts at once
    # (fixes: loop was overwriting os_scan_log each iteration, discarding all but the last host)
    logger.info(f"Running OS detection scan for all {len(discovered_hosts)} hosts...")
    os_scan_log = nmap_scanning.invoke({
        "scan_type": "high",
        "flags": os_scan_flags,
        "targets": discovered_hosts,
        "timeout": TIMEOUT_VAL
    })

    # write to scan log dump
    with open(SCANNING_DUMP_LOG, "a") as f:
        f.write(f"\n\n [OS FINGERPRINTING SCAN] [{_now()}]")
        f.write(f"\nTargets: {discovered_hosts}")
        f.write(f"\nFlags: {os_scan_flags}")
        f.write(f"\nSuccess: {os_scan_log.get('success')}\n")

    # parse the OS fingerprinting results
    os_results = {}
    if os_scan_log.get("success") and os_scan_log.get("xml_file"):
        xml_path = f"{os_scan_log['xml_dir']}/{os_scan_log['xml_file']}"
        logger.info(f"xml path for OS fingerprinting is defined as: {xml_path}")

        # parse the XML for OS data
        parsed_data = xml_parse(xml_path)

        # extract the OS information
        for host_ip, host_data in parsed_data.items():
            os_info = host_data.get("os", {})

            os_results[host_ip] = {
                "os_matches": os_info.get("matches", []),  # List of possible OS matches
                "os_classes": os_info.get("classes", []),   # OS classification data
                "fingerprint": os_info.get("fingerprint", ""),  # TCP/IP fingerprint
                "ports_used": os_info.get("ports_used", []),  # Ports used for detection
                "accuracy": os_info.get("accuracy", 0),  # Detection confidence
                "cpe": os_info.get("cpe", []),  # CPE identifiers for vuln correlation
                "device_type": os_info.get("device_type", "unknown"),
                "vendor": os_info.get("vendor", "unknown")
            }

        # read and store the XML content
        with open(xml_path, "r", encoding="utf-8") as f:
            state["os_xml_content"] = f.read()

    # store the results in state
    state["os_fingerprint_results"] = os_results

    logger.info("OS fingerprinting completed, state has also been updated")

    return state