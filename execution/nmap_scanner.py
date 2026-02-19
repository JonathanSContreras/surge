"""
@author: Brianna Hinds
Description: Tool method definitions for Surge MAS.
"""
# imports
from config.constants import TIMEOUT_VAL
from config.logging_config import get_logger
from governance.sanitization import sanitize_flags_for_tier
from utils.helpers import store_xml_to_folder

from langchain.tools import tool
import subprocess
import datetime
import time
import shlex

# define global logging file
logger = get_logger(__name__)

## --- RECON METHOD/TOOLS --- ##
@tool
def nmap_scanning(scan_type: str, flags: list[str], targets: list[str], timeout: int = TIMEOUT_VAL) -> dict:
    """
    Run an nmap scan in a safe, tiered manner.

    Returns JSON only. Structure:
    {
        "timestamp": ISO timestamp,
        "command": [...],
        "targets": [...],
        "xml_dir": xml_folder_path as a string,
        "xml_file": xml file just created as a string
        "stderr": "...",
        "returncode": 0,
        "success": true/false,
        "max_runtime_s": float
    }

    The LLM must not output human-readable messages, only JSON.
    """

    # import logging, subprocess, shlex, time, datetime

    # logging.basicConfig(level=logging.DEBUG)
    # logger = logging.getLogger("NMAP_SCANNER")

    ## --- ROBUST CHECKS --- ##
    # check flags content
    if not isinstance(flags, list):
        return {"error": "flags must be a list"}

    # check the target list content
    if not isinstance(targets, list) or len(targets) == 0:
        return {"error": "targets must be a non-empty list"}

    flags_flat = []
    for f in flags:
        flags_flat.extend(shlex.split(f))  # split commands like "-p1-1024" vs multi tokens
    ## --------- ##

    ## --- SANITIZATION --- ##
    sanitized = sanitize_flags_for_tier(flags_flat, scan_type)
    if isinstance(sanitized, dict) and "error" in sanitized:
        return sanitized  # return the error directly
    
    flags_flat = sanitized

    # scan variables
    cmd = ["nmap"] + flags_flat + targets
    start_time = time.time()
    timestamp = datetime.datetime.now().isoformat() + "Z"
    # logger.debug("Running command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        
        # write the xml output to a .xml file store it in a folder
        safe_timestamp = timestamp.replace(":", "_").replace(".", "_")  # '2025-10-15T12-45-59-442649'
        file_path = f"{safe_timestamp}_nmap.xml"

        # ensure stdout is text
        xml_output = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8")

        # link that folder name to the "xml" key
        folder_path = store_xml_to_folder(targets, xml_output, file_path)

        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml_dir": folder_path,
            "xml_file": file_path,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        # log_history(log)
        return log
    except subprocess.TimeoutExpired:
        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml_dir": None,
            "xml_file": None,
            "stderr": "~SCAN TIMED OUT",
            "returncode": None,
            "success": False,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        # log_history(log)
        return log