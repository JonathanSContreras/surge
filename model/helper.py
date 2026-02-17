"""
@author: Brianna Hinds
Description: Helper functions for the agents.
"""
from globals import SANITIZATION_TIER_CONFIG, METACHARACTERS, SCAN_RESULTS_DIR
import re
import json
import datetime
import xml.etree.ElementTree as ET
import os
import json
from typing import Any

## --- SANITIZATION METHODS --- ##
def _extract_port_expressions(flags: list[str]) -> list[str]:
    """
    Extracts any port expressions from the provided flag tokens.
    Examples: "-p22", "-p1-1024", "-p22,80,443" or ["-p", "22,80,443"].
    """
    port_exprs = []
    i = 0
    while i < len(flags):
        tok = flags[i]
        if tok == "-p" and i + 1 < len(flags):
            port_exprs.append(flags[i+1])
            i += 2
            continue
        if tok.startswith("-p") and len(tok) > 2:
            port_exprs.append(tok[2:])
        i += 1
    return port_exprs


def _validate_port_expr(expr: str, max_port: int) -> bool:
    """
    Returns True if all ports in the expression are within range.
    Supports single, ranges, and comma-separated lists.
    """
    for part in expr.split(","):
        if "-" in part:
            try:
                low, high = part.split("-", 1)
                low, high = int(low), int(high)
            except ValueError:
                return False
            if low < 0 or high < 0 or high > max_port:
                return False
        else:
            try:
                port = int(part)
            except ValueError:
                return False
            if port < 0 or port > max_port:
                return False
    return True


def sanitize_flags_for_tier(flags: list[str], tier: str):
    """
    Validate and sanitize tokenized flag list based on the tier requested.
    Returns a sanitized list of tokens OR {"error": "MESSAGE"}
    """
    config = SANITIZATION_TIER_CONFIG.get(tier)
    if config is None:
        return {"error": f"unknown tier value: {tier}"}

    # check for metacharacters
    combined_tokens = " ".join(flags)
    if any(m in combined_tokens for m in METACHARACTERS):
        return {"error": "~DISALLOWED SHELL/OPERATOR IN FLAGS"}

    allowed = config["allowed_flags"]
    max_port_range = config["max_port_range"]

    sanitized_flags = []
    i = 0
    while i < len(flags):
        tok = flags[i]

        # keep positional tokens only if they are script args handled below,
        # otherwise positional tokens are suspicious (likely user error)
        if not tok.startswith("-"):
            # treat bare tokens as possible script names only if previous token was --script (handled below)
            # otherwise, keep them — they might be legitimate (some flags accept bare args)
            sanitized_flags.append(tok)
            i += 1
            continue

        # timing flags like -T4
        if tok.startswith("-T") and any(t.startswith("-T") for t in allowed):
            sanitized_flags.append(tok)
            i += 1
            continue

        # output flags: accept -oX and -oN and allow a following "-" or file path
        if tok in ("-oX", "-oN", "-oG", "-oA"):
            sanitized_flags.append(tok)
            # include next token if it exists and is not another flag (e.g., '-' or filename)
            if i + 1 < len(flags) and not flags[i+1].startswith("-"):
                sanitized_flags.append(flags[i+1])
                i += 2
            else:
                i += 1
            continue

        # -p forms
        if tok == "-p":
            # keep the -p only if allowed and next token is a port expr within range
            if "-p" in allowed and i + 1 < len(flags) and _validate_port_expr(flags[i+1], max_port_range):
                sanitized_flags.append("-p")
                sanitized_flags.append(flags[i+1])
            # skip the port and its arg otherwise
            i += 2
            continue
        if tok.startswith("-p") and "-p" in allowed:
            expr = tok[2:]
            if _validate_port_expr(expr, max_port_range):
                sanitized_flags.append(tok)
            i += 1
            continue
        if tok.startswith("-p") and "-p" not in allowed:
            # discard any -p forms when not allowed
            i += 1
            continue

        # --script handling (support both "--script name" and "--script=name")
        if tok.startswith("--script"):
            if "--script" not in allowed:
                # script usage not allowed for this tier
                i += 1
                continue

            # case: --script=name
            if "=" in tok:
                sanitized_flags.append(tok)
                i += 1
                continue

            # case: --script <name>
            if i + 1 < len(flags) and not flags[i+1].startswith("-"):
                sanitized_flags.append(tok)
                sanitized_flags.append(flags[i+1])
                i += 2
                continue
            else:
                # standalone --script with no argument
                i += 1
                continue

        # generic allowed-flag check (applies to all tiers)
        if tok in allowed:
            sanitized_flags.append(tok)
            i += 1
            continue

        # allow flags that start with allowed prefixes
        if any(tok.startswith(pref) for pref in allowed if pref.endswith("-") or pref.endswith("_")):
            sanitized_flags.append(tok)
            i += 1
            continue

        # if we reach here, token is not allowed
        i += 1

    # ensure XML output is requested, if not, add "-oX -"
    has_oX = any(x == "-oX" or x.startswith("-oX") for x in sanitized_flags)
    if not has_oX:
        sanitized_flags.extend(["-oX", "-"])

    return sanitized_flags


## --- JSON FUNCTIONS -- ##
# def extract_json(raw_text: str, iteration: int) -> dict:
#     """
#     Tries to extract JSON from the model output.
#     If invalid or missing, logs the issue and returns an empty dict.
#     """
#     # Try to find JSON block
#     match = re.search(r"\{[\s\S]*\}", raw_text)
#     if not match:
#         print(f"[{datetime.datetime.now()}] ~ WARNING: No JSON block found in iteration {iteration}")
#         return {}

#     try:
#         parsed = json.loads(match.group(0))
#         print(f"[{datetime.datetime.now()}] ~ Extracted valid JSON decision.")
#         return parsed
#     except json.JSONDecodeError as e:
#         print(f"[{datetime.datetime.now()}] ~ Invalid JSON at iteration {iteration}: {e}")
#         return {}

def extract_json(raw_text: str, iteration: int | None = None) -> Any:
    """
    Extracts the FIRST valid JSON object or array from raw LLM output.
    Supports both `{}` and `[]`.
    """

    if not raw_text or not raw_text.strip():
        print(f"[{datetime.datetime.now()}] ~ EMPTY MODEL OUTPUT")
        return None

    # Try array first (vuln agents, formatters)
    array_match = re.search(r"\[[\s\S]*\]", raw_text)
    if array_match:
        try:
            parsed = json.loads(array_match.group(0))
            print(f"[{datetime.datetime.now()}] ~ Extracted valid JSON ARRAY")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[{datetime.datetime.now()}] ~ Invalid JSON ARRAY: {e}")

    # Fallback: try object (recon agent)
    obj_match = re.search(r"\{[\s\S]*\}", raw_text)
    if obj_match:
        try:
            parsed = json.loads(obj_match.group(0))
            print(f"[{datetime.datetime.now()}] ~ Extracted valid JSON OBJECT")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[{datetime.datetime.now()}] ~ Invalid JSON OBJECT: {e}")

    print(f"[{datetime.datetime.now()}] ~ NO VALID JSON FOUND")
    return None


## --- RECON AGENT HELPER METHODS --- ##
def target_to_proper_file_name(target: list):
    """
    Takes the scan target list and turns it into a valid file name.
    Returns a string type of the file name.

    Args
        target: user inputted target value in list format
    """
    valid_file_name = re.sub(r"[^A-Za-z0-9_-]", "_", "".join(target))

    return valid_file_name

def xml_parse_v1(xml_data):
    """
    Parses Nmap XML output into a structured dictionary.
    Handles missing fields and multiple addresses/hostnames.
    Returns a dictionary with ONLY IPv4 addresses as keys.

    Args
        xml_data: .xml file path or XML string to be parsed.
    """
    import re
    
    network_config = {}
    
    # IPv4 validation pattern
    ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

    if not xml_data:
        return {}

    # Parse XML (from file or string)
    try:  
        if os.path.exists(xml_data):  # file parse
            tree = ET.parse(xml_data)
            root = tree.getroot()
        else:  # string parse
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
        # --- Extract addresses (IPv4 only as host identifier) ---
        ipv4_addr = None
        mac_addr = None
        mac_vendor = None
        
        for addr_elem in host.findall("address"):
            addr = addr_elem.attrib.get("addr")
            addrtype = addr_elem.attrib.get("addrtype")
            
            if addrtype == "ipv4" and ipv4_pattern.match(addr):
                ipv4_addr = addr
            elif addrtype == "mac":
                mac_addr = addr
                mac_vendor = addr_elem.attrib.get("vendor", "unknown")
        
        # Skip this host if no valid IPv4 address found
        if not ipv4_addr:
            continue

        # --- Extract hostnames ---
        hostnames = []
        for hostname_elem in host.findall("hostnames/hostname"):
            name = hostname_elem.attrib.get("name")
            if name:
                hostnames.append(name)

        # --- Extract status ---
        status = "unknown"
        status_elem = host.find("status")
        if status_elem is not None:
            status = status_elem.attrib.get("state", "unknown")

        # --- Extract ports and services ---
        services = []
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
                        "extrainfo": service_elem.attrib.get("extrainfo"),
                        "ostype": service_elem.attrib.get("ostype"),
                        "method": service_elem.attrib.get("method"),
                        "conf": service_elem.attrib.get("conf")
                    })
                    
                    # Extract CPE identifiers
                    cpes = []
                    for cpe_elem in service_elem.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text)
                    if cpes:
                        port_data["cpe"] = cpes
                else:
                    port_data.update({
                        "service": "unknown", 
                        "product": None, 
                        "version": None, 
                        "extrainfo": None
                    })

                services.append(port_data)

        # --- Extract OS information ---
        os_info = {}
        os_elem = host.find("os")
        if os_elem is not None:
            # Get all OS matches
            os_matches = []
            for osmatch in os_elem.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.attrib.get("name"),
                    "accuracy": int(osmatch.attrib.get("accuracy", 0)),
                    "line": osmatch.attrib.get("line")
                })
            
            # Get OS classes
            os_classes = []
            for osclass in os_elem.findall(".//osclass"):
                os_classes.append({
                    "type": osclass.attrib.get("type"),
                    "vendor": osclass.attrib.get("vendor"),
                    "osfamily": osclass.attrib.get("osfamily"),
                    "osgen": osclass.attrib.get("osgen"),
                    "accuracy": int(osclass.attrib.get("accuracy", 0))
                })
            
            # Get CPE identifiers from OS detection
            cpes = []
            for cpe_elem in os_elem.findall(".//cpe"):
                if cpe_elem.text:
                    cpes.append(cpe_elem.text)
            
            # Get ports used for OS detection
            ports_used = []
            for portused in os_elem.findall("portused"):
                ports_used.append({
                    "state": portused.attrib.get("state"),
                    "proto": portused.attrib.get("proto"),
                    "portid": portused.attrib.get("portid")
                })
            
            # Get OS fingerprint
            osfingerprint = os_elem.find("osfingerprint")
            fingerprint = osfingerprint.attrib.get("fingerprint", "") if osfingerprint is not None else ""
            
            os_info = {
                "matches": os_matches,
                "classes": os_classes,
                "cpe": cpes,
                "ports_used": ports_used,
                "fingerprint": fingerprint,
                "accuracy": os_matches[0]["accuracy"] if os_matches else 0,
                "device_type": os_classes[0]["type"] if os_classes else "unknown",
                "vendor": os_classes[0]["vendor"] if os_classes else "unknown"
            }

        # --- Extract uptime ---
        uptime_seconds = None
        uptime_elem = host.find("uptime")
        if uptime_elem is not None:
            uptime_seconds = uptime_elem.attrib.get("seconds")

        # --- Build host entry (use IPv4 as key) ---
        network_config[ipv4_addr] = {
            "status": status,
            "mac_address": mac_addr,
            "mac_vendor": mac_vendor,
            "hostnames": hostnames if hostnames else [],
            "services": services,
            "os": os_info,
            "uptime_seconds": uptime_seconds
        }

    return network_config
# def xml_parse_v1(xml_data):
#     """
#     Parses Nmap XML output into a structured dictionary.
#     Handles missing fields and multiple addresses/hostnames.
#     Returns a dictionary type data structure of all nodes, devices, connections, etc.

#     Args
#         xml_data: .xml file definition that will become parsed.
#     """
#     network_config = {}

#     if not xml_data:
#         return {}

#     # Parse XML (from file or string)
#     try:  
#         if os.path.exists(xml_data):  # file parse
#             tree = ET.parse(xml_data)
#             root = tree.getroot()
#         else:  # string parse
#             s = xml_data.strip()
#             print("printing s", s)
#             if not s.startswith("<"):
#                 return {"error": "~INPUT DOES NOT APPEAR TO BE XML"}
#             root = ET.fromstring(s)
#     except ET.ParseError as pe:
#         return {"error": f"~ISSUE PARSING ELEMENTTREE: {pe}"}
#     except Exception as e:
#         return {"error": f"~UNEXPECTED ERROR PARSING XML: {e}"}

#     # Iterate over each host
#     for host in root.findall("host"):
#         addresses = []
#         hostnames = []

#         # --- Extract addresses ---
#         for addr_elem in host.findall("address"):
#             addr = addr_elem.attrib.get("addr")
#             addrtype = addr_elem.attrib.get("addrtype")
#             if addr:
#                 addresses.append({"addr": addr, "type": addrtype or "unknown"})

#         # --- Extract hostnames ---
#         for hostname_elem in host.findall("hostnames/hostname"):
#             name = hostname_elem.attrib.get("name")
#             if name:
#                 hostnames.append(name)

#         # --- Extract ports ---
#         ports_list = []
#         ports_elem = host.find("ports")
#         if ports_elem is not None:
#             for port in ports_elem.findall("port"):
#                 port_data = {
#                     "port": port.attrib.get("portid"),
#                     "protocol": port.attrib.get("protocol"),
#                 }

#                 # Extract state
#                 state_elem = port.find("state")
#                 if state_elem is not None:
#                     port_data.update({
#                         "state": state_elem.attrib.get("state", "unknown"),
#                         "reason": state_elem.attrib.get("reason", "unknown"),
#                         "reason_ttl": state_elem.attrib.get("reason_ttl", "unknown"),
#                     })
#                 else:
#                     port_data.update({"state": "unknown", "reason": None, "reason_ttl": None})

#                 # Extract service
#                 service_elem = port.find("service")
#                 if service_elem is not None:
#                     port_data.update({
#                         "service": service_elem.attrib.get("name", "unknown"),
#                         "product": service_elem.attrib.get("product"),
#                         "version": service_elem.attrib.get("version"),
#                         "extrainfo": service_elem.attrib.get("extrainfo")
#                     })
#                 else:
#                     port_data.update({"service": "unknown", "product": None, "version": None, "extrainfo": None})

#                 ports_list.append(port_data)

#         # --- Assign to all addresses ---
#         for addr in addresses:
#             network_config[addr["addr"]] = {
#                 "addr_type": addr["type"],
#                 "hostnames": hostnames or ["unknown"],
#                 "ports": ports_list
#             }

#     return network_config

def store_xml_to_folder(target: list, scan_output: str, xml_file: str, base_folder: str=SCAN_RESULTS_DIR) -> str:   # this will take all of the xml files generated and store it in a folder
    """
    Creates a directory named after the given target (if it doesn't already exist)
    and stores an XML file in that directory.
    Returns a path to the directory where the file was saved.

    Args
        target: list of strings that represent the target identifier (e.g., hostnames or file parts)
        scan_output: .xml content to be written to the file as a string
        xml_file: name of the XML file (should include `.xml` extension)
    """
    # Create base folder if it doesn't exist
    os.makedirs(base_folder, exist_ok=True)

    # # create directory
    # target_name = target_to_proper_file_name(target)
    # directory_name = f"./{target_name}"

    # make directory and add xml file into it
    # os.makedirs(directory_name, exist_ok=True)
    # new_xml_path = f"{directory_name}/{xml_file}"
    new_xml_path = os.path.join(base_folder, xml_file)

    with open(new_xml_path, "w", encoding="utf-8") as f:
        f.write(scan_output)

    print(f"Successfully saved .xml file to folder {base_folder}.")

    return base_folder

def all_xml_output_to_txt(target_file: str) -> str:
    """
    Takes all xml content from the scan folder and outputs it to a txt file.
    Returns the string path value.
    """
    xml_folder = target_file

    # pull the folder name (the target value passes as a proper file string)
    xml_list = sorted(f for f in os.listdir(xml_folder) if f.endswith(".xml"))
    content = ""  # define an empty content variable

    # go through each xml file and get its content
    for xml in xml_list:
        xml_path = os.path.join(xml_folder, xml)  # ./TARGET/XML PATH
        if os.path.isfile(xml_path):
            with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
                content += data
                content += "\n < --- END OF XML CONTENT --- > \n"
                print("SUCCESSFULLY RETRIEVED ALL XML CONTENT")

    # add the content to a txt file (used later for the recon analysis and vulnerability agent)
    output_path = f"{xml_folder}/xml_content.txt"
    with open(output_path, "w") as c:
        c.write(content)
        print("SUCCESSFULLY WROTE ALL CONTENT TO A TXT")

    return output_path


## --- RECON ANALYZER HELPER METHOD -- ##
# THIS IS A TEST METHOD 
def summarize_recon_results(recon_results: dict) -> dict:
    """Return counts for LLM prompt from raw recon results."""
    open_ports = 0
    service_count = 0
    os_fingerprint_count = 0
    discovered_hosts = set()

    for host, data in recon_results.items():
        discovered_hosts.add(host)
        ports = data.get("ports", [])
        open_ports += sum(1 for p in ports if p.get("state") == "open")
        service_count += sum(1 for p in ports if p.get("service_version"))
        if data.get("os"):
            os_fingerprint_count += 1

    return {
        "open_ports_count": open_ports,
        "service_count": service_count,
        "os_fingerprint_count": os_fingerprint_count,
    }


## --- VULNERABILITY AGENT HELPER FUNCTIONS --- ##


