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
import json
import shlex
from helper import sanitize_flags_for_tier
from globals import TIMEOUT_VAL, LOG_FILE  # configuration file

## --- RECON METHOD/TOOLS --- ##
def xml_parse(xml_data):
    """
    Parses nmap XML output into structured dictionary form.
    Handles missing fields gracefully.
    """
    import xml.etree.ElementTree as ET
    network_config = {}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        print("⚠️ XML parsing error: malformed data")
        return {}

    for host in root.findall("host"):
        host_addr = None
        host_name = None
        port_lst = []  # ✅ Always initialize this

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
                "ports": port_lst,  # ✅ Safe even if empty
            }

    return network_config


def xml_parse_v1(xml_input: str) -> dict:
    """
    Reads a either an XML file or a string XML output and parses it storing network information. 
    Returns the nmap command used and a dictionary of important network components.

    ARGS
        xml_input: nmap scan .xml output
    """
    if not xml_input:
        return {}
    
    # get the xml_ouput (either string or XML file)
    try:
        if os.path.exists(xml_input):
            tree = ET.parse(xml_input)
            root = tree.getroot()
        else:
            s = xml_input.strip()

            if not (s.startswith("<")):  # check if the string is XML looking
                return {"error": "~INPUT DOES NOT APPEAR TO BE XML"}
            
            root = ET.fromstring(s)

    except ET.ParseError as pe:
        return {"error": f"~ISSUE PARSING ELEMENTTREE: {pe}"}
    except Exception as e:
        return {"error": f"~UNEXPECTED ERROR PARSING XML: {e}"}

    # loop over root children and their sub attributes
    # network info will be housed in a dictionary
    network = {}
    for child in root: 
        network_config = {}

        # skip over none host elements
        if child.tag != "host":
            continue

        # pull all IP hosts found (up/down)
        addr = child.findall("address")  # might not be universal (can have ipv4/mac)
        ip_addr = None
        mac_addr = None
        for a in addr:
            # store ipv4 as the main key
            if a.attrib["addrtype"] == "ipv4":
                ip_addr = a.attrib["addr"]

            # if a mac address exists store it
            if a.attrib["addrtype"] == "mac":
                # store other address types
                mac_addr = a.attrib["addr"]
                vendor = a.attrib.get("vendor", None)
                network_config["address"] = {"mac_addr" : mac_addr, "vendor": vendor}

        # use mac as main key if ipv4 not available
        if not ip_addr and mac_addr is not None:
            print("~NO IPV4 VALUE USING MAC INSTEAD")
            ip_addr = mac_addr
            
        # find host's state
        status = child.find("status").attrib["state"]
        if status != "up":  # host is down
            network_config["os"] = None
            network_config["state"] = None
            network_config["hostname"] = None
            network_config["ports"] = None
        else:   # host is up
            # find IP hostname (might contain multiple or none)
            hostname_root = child.find("hostnames")
            if hostname_root is not None:
                hostname_list = []
                for host in hostname_root:
                    hostname_list.append(host.attrib) 
            else:
                hostname_list = None

            # find IP OS (either single or multiple)
            os_root = child.find("os")
            if os_root is not None:
                osmatch = os_root.findall("osmatch")
                os_lst = []
                for o in osmatch:
                    os_pred = o.attrib
                    os_lst.append(os_pred)
                network_config["os"] = os_lst
            else: 
                network_config["os"] = None

            network_config["state"] = status 
            network_config["hostname"] = hostname_list  # store list of hostnames if contains multiple

            # find IP open ports
            port_root = child.find("ports")
            if port_root is not None:
                port_lst = []
                for port in port_root.findall("port"):
                    port_data = dict(port.attrib)
                    for child in port:
                        if child.tag in ("state", "service"):
                            port_data.update(child.attrib)
                    port_lst.append(port_data)

            network_config["ports"] = port_lst

        # add the host into the dictionary
        network[ip_addr] = network_config

    return network

def log_history(entry):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(entry) + "\n")
    
    except Exception as e:
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
    print(cmd)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            timeout=timeout
        )

        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        log_history(log)
        print(cmd)  # DEBUG
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
        print(cmd)  # DEBUG
        return log


## --- VULNERABILITY TOOLS --- ##
# use openvas