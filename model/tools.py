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

## --- CONFIGURATIONS --- ##
TIMEOUT_VAL = 300
# RATE_LIMIT = 2
# ALLOWED_FLAGS = []
# DISALLOWED_FLAGS = []
LOG_FILE = "./utils/scan_history.json"

## --- RECON METHOD/TOOLS --- ##
def xml_parse(xml_file: str) -> dict:
    """
    Reads a .xml file and parses it storing network information. 
    Returns the nmap command used and a dictionary of important network components.

    ARGS
        xml_file: nmap scan .xml output
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()  # tag that envelopes everything (SAM)
    # scan_command = root.attrib["args"]

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
def nmap_scanning(request: str) -> dict:
    """
    Run an nmap request. `request` HAS to be a string and has to contain -oX to output it as a XML file:
      - a string like: "nmap -sV -p 1-1024 192.168.1.0/24"

    Returns a dict:
      {
        "timestamp": ISO timestamp,
        "command": ["nmap","-sV",...],
        "targets": [...],
        "xml": "<...>" or None,
        "stderr": "...",
        "returncode": 0,
        "success": bool,
        "runtime_s": float,
        "validation": "OK" or "reason",
        "history_id": optional
      }
    """

    # variable definitions
    start_time = time.time()
    timestamp = datetime.datetime.now().isoformat() + "Z"
    cmd = request.lower().split()   # turns the command into a list

    ## --- ROBUST CHECKS --- ##
    # check for shell metacharacters
    for m in (";", "&&", "||", "`", "$("):
        if m in cmd:
            return {"error": "command contains not allowed shell operators"}

    # check if request is a string
    if not isinstance(request, str):
        return {"error": "request must be a string"}
    
    # check if the -oX is in the list
    if "-oX" not in cmd:
        return {"error": "scan must contain, -oX, so it can output an XML"}


    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            timeout=TIMEOUT_VAL
        )
        return {
            "timestamp": timestamp,
            "command": request,
            "xml": proc.stdout,
            "stderr": proc.stderr,
            "success": proc.returncode == 0,
            "process_time": round(time.time()-start_time, 2)
        }
    except subprocess.TimeoutExpired:
        return {
            "timestamp": timestamp,
            "command": request,
            "xml": "",
            "stderr": "Scan timed out.",
            "success": False,
            "process_time": round(time.time()-start_time, 2)
        }


## --- VULNERABILITY TOOLS --- ##
# use openvas