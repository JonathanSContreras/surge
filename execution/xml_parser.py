import os
import xml.etree.ElementTree as ET

def xml_parse(xml_data) -> dict:
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
