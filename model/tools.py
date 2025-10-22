"""
@author: Brianna Hinds
Description: Tool method definitions for Surge MAS.
"""
# imports
from langchain.tools import tool
import xml.etree.ElementTree as ET
import subprocess
import os
import datetime
import time
import shlex
from helper import sanitize_flags_for_tier
from globals import TIMEOUT_VAL, SCANNING_DUMP_LOG  # configuration file

## --- RECON METHOD/TOOLS --- ##
def xml_parse(xml_data):
    """
    Parses nmap XML output into structured dictionary form.
    Handles missing fields gracefully.
    """
    network_config = {}
    
    # nothing in the xml file
    if not xml_data:
        return {}
    
    # get the xml_ouput (either string or XML file)
    try:
        if os.path.exists(xml_data):
            tree = ET.parse(xml_data)
            root = tree.getroot()
        else:
            s = xml_data.strip()

            if not (s.startswith("<")):  # check if the string is XML looking
                return {"error": "~INPUT DOES NOT APPEAR TO BE XML"}
            
            root = ET.fromstring(s)

    except ET.ParseError as pe:
        return {"error": f"~ISSUE PARSING ELEMENTTREE: {pe}"}
    except Exception as e:
        return {"error": f"~UNEXPECTED ERROR PARSING XML: {e}"}

    for host in root.findall("host"):
        host_addr = None
        host_name = None
        port_lst = [] 

        # --- Extract address ---
        addr_elem = host.find("address")
        if addr_elem is not None:
            host_addr = addr_elem.attrib.get("addr")

        # --- Extract hostname (optional) ---
        hostnames_elem = host.find("hostnames/hostname")
        if hostnames_elem is not None:
            host_name = hostnames_elem.attrib.get("name")

        # --- Extract ports (if any) ---
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_id = port.attrib.get("portid")
                protocol = port.attrib.get("protocol")
                state_elem = port.find("state")
                service_elem = port.find("service")

                state = state_elem.attrib.get("state") if state_elem is not None else "unknown"
                service = service_elem.attrib.get("name") if service_elem is not None else "unknown"

                port_lst.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service
                })

        # --- Store host summary ---
        if host_addr:
            network_config[host_addr] = {
                "hostname": host_name or "unknown",
                "ports": port_lst, 
            }

    return network_config


def xml_parse_v1(xml_data):
    """
    Parses Nmap XML output into a structured dictionary.
    Handles missing fields and multiple addresses/hostnames.
    """
    network_config = {}

    if not xml_data:
        return {}

    # Parse XML (from file or string)
    try:
        if os.path.exists(xml_data):
            tree = ET.parse(xml_data)
            root = tree.getroot()
        else:
            s = xml_data.strip()
            if not s.startswith("<"):
                return {"error": "~INPUT DOES NOT APPEAR TO BE XML"}
            root = ET.fromstring(s)
    except ET.ParseError as pe:
        return {"error": f"~ISSUE PARSING ELEMENTTREE: {pe}"}
    except Exception as e:
        return {"error": f"~UNEXPECTED ERROR PARSING XML: {e}"}

    # Iterate over each host
    for host in root.findall("host"):
        addresses = []
        hostnames = []

        # --- Extract addresses ---
        for addr_elem in host.findall("address"):
            addr = addr_elem.attrib.get("addr")
            addrtype = addr_elem.attrib.get("addrtype")
            if addr:
                addresses.append({"addr": addr, "type": addrtype or "unknown"})

        # --- Extract hostnames ---
        for hostname_elem in host.findall("hostnames/hostname"):
            name = hostname_elem.attrib.get("name")
            if name:
                hostnames.append(name)

        # --- Extract ports ---
        ports_list = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_data = {
                    "port": port.attrib.get("portid"),
                    "protocol": port.attrib.get("protocol"),
                }

                # Extract state
                state_elem = port.find("state")
                if state_elem is not None:
                    port_data.update({
                        "state": state_elem.attrib.get("state", "unknown"),
                        "reason": state_elem.attrib.get("reason", "unknown"),
                        "reason_ttl": state_elem.attrib.get("reason_ttl", "unknown"),
                    })
                else:
                    port_data.update({"state": "unknown", "reason": None, "reason_ttl": None})

                # Extract service
                service_elem = port.find("service")
                if service_elem is not None:
                    port_data.update({
                        "service": service_elem.attrib.get("name", "unknown"),
                        "product": service_elem.attrib.get("product"),
                        "version": service_elem.attrib.get("version"),
                        "extrainfo": service_elem.attrib.get("extrainfo")
                    })
                else:
                    port_data.update({"service": "unknown", "product": None, "version": None, "extrainfo": None})

                ports_list.append(port_data)

        # --- Assign to all addresses ---
        for addr in addresses:
            network_config[addr["addr"]] = {
                "addr_type": addr["type"],
                "hostnames": hostnames or ["unknown"],
                "ports": ports_list
            }

    return network_config

def log_history(entry):
    print(os.path.exists(SCANNING_DUMP_LOG))
    try:
        with open(SCANNING_DUMP_LOG, "a") as lf:
            print("WRITING TO DUMP LOG in tools.py")
            lf.write(entry + "\n")
    
    except Exception as e:
        print("Failed to write to dump in tools.py")
        pass

@tool
def nmap_scanning(scan_type: str, flags: list[str], targets: list[str], timeout: int = TIMEOUT_VAL) -> dict:
    """
    Run an nmap scan in a safe, tiered manner.

    Returns JSON only. Structure:
    {
        "timestamp": ISO timestamp,
        "command": [...],
        "targets": [...],
        "xml": "<xml string>",
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
        
        # write the xml output to a .xml file and then link it in the "xml"
        safe_timestamp = timestamp.replace(":", "_").replace(".", "_")  # '2025-10-15T12-45-59-442649'
        file_path = f"./data/{safe_timestamp}_nmap.xml"

        # ensure stdout is text
        xml_output = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8")

        # ROBUST CHECK ##
        # print(os.path.isdir("../data"))
        ####

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(xml_output)
        # with open(file_path, "w+", encoding="utf-8") as f:
        #     f.write(proc.stdout)

        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml": file_path,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        log_history(log)
        return log
    except subprocess.TimeoutExpired:
        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml": None,
            "stderr": "~SCAN TIMED OUT",
            "returncode": None,
            "success": False,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        log_history(log)
        return log


## --- VULNERABILITY TOOLS --- ##
# use openvas