from utils.helpers import score_conversion
from utils.topology import build_topology
from config.logging_config import get_logger
from execution.xml_parser import xml_parse
from core.state import AgentState

from typing import Any
import os
import json

"""
NOTES:
- I personally want this file to call xml_parser.py for all xml outputs to build dictionaries per xml file
- WILL NEED TO have a .xml output for the os fingerprint scan
- merge all the dictionaries where the key is the IP address
"""
# define global log file
logger = get_logger(__name__)

## --- PREPROCESSING METHODS --- ##
def _derive_xml_data() -> list[dict[str, Any]]:
    """
    Docstring for build_dashboard_payload
    
    :param state: Description
    :type state: AgentState
    :return: Description
    :rtype: list[dict[str, Any]]
    """

    # create dictionaries for each xml file outputted
    xml_data = []
    
    # parse /scan_results for files that end in .xml
    xml_dir = "./scan_results"  # NOTE: make sure the os fingerprint scan goes in ./scan_results
    if os.path.isdir(xml_dir):
        for root, _, files in os.walk(xml_dir, topdown=True):  # root -> ./scan_results, files = list of all files in folder
            for filename in sorted(files):
                file_dict = {}  # creating a new dictionary per filename parse
                # only parse .xml files
                if not filename.endswith(".xml"):
                    continue

                # create the full file path
                file_to_parse = os.path.join(root, filename)
                logger.info(f"Parsing {filename} in dir: {root}")

                # call the parser
                file_dict = xml_parse(file_to_parse)

                # append the dictionary in the list
                xml_data.append(file_dict)

    return xml_data

def _update_vuln_scoring(vuln_scoring: list[dict]) -> list[dict]:
    # go through each dictionary in the list
    for v in vuln_scoring:
        # grab the predicted score and add the word value
        score = v.get("predicted_score", 0.0)
        word = score_conversion(score)
        v["severity"] = word

    return vuln_scoring

# grab formatting method
def dashboard_data_grab(
    vuln_scoring: AgentState,
    discovered_hosts: set | list | None = None,
    parsed_network: dict | None = None,
) -> dict:
    """
    // json output format example
    {
        "id": "1",  // string (maybe can be order of object/index)
        "ip": "192.168.1.1",
        "severity": "critical",  // defining a word for a range
        "description": "Primary gateway ...",
        "deviceType": "router", // IoT, etc
        "hostname": "gateway-primary",
        "cvss": 9.8,  // float from cvss scorer
        "status": "up"  //up or down
    }
    """
    # compute severity from predicted_score for every entry before building dashboard
    vuln_scoring = _update_vuln_scoring(vuln_scoring)

    # Prefer the cumulative parsed_network from state — it's already deduplicated by IP
    # and contains the richest service data across all recon iterations.
    # Fall back to reading all XML files from disk only when no in-memory data is available.
    if parsed_network:
        host_dicts = list(parsed_network.values())
        logger.info(f"Building dashboard from in-memory parsed_network ({len(host_dicts)} hosts)")
    else:
        logger.warning("No parsed_network in state — falling back to reading all XML files from disk")
        xml_data = _derive_xml_data()
        host_dicts = []
        seen_ips: set = set()
        for n in xml_data:
            if "error" in n:
                logger.warning(f"Skipping unparseable XML: {n['error']}")
                continue
            for key in n.keys():
                host = n[key]
                ip = host.get("ip")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    host_dicts.append(host)

    # normalize discovered_hosts to a set for O(1) lookup; None means no filter
    host_filter = set(discovered_hosts) if discovered_hosts is not None else None

    dashboard_data = []
    i = 1
    for host in host_dicts:
        ip          = host.get("ip")
        status      = host.get("status", "down")
        description = host.get("description", "no description found")
        services    = host.get("services", [])
        os_info     = host.get("os", {})
        hostnames   = host.get("hostnames", [])

        if not ip:
            continue

        # skip IPs not confirmed by the recon delta-detection loop
        if host_filter is not None and ip not in host_filter:
            continue

        # skip ghost hosts: nmap marked up via -Pn with no actual open ports
        # but keep hosts that have vulnerabilities (real hosts behind a firewall)
        has_vulns = any(v.get("host", v.get("ip")) == ip for v in vuln_scoring)
        if not services and not has_vulns:
            logger.debug(f"Skipping ghost host {ip} — no services or vulnerabilities detected")
            continue

        deviceType = os_info.get("device_type") or None
        hostname   = hostnames[0] if hostnames else "idk"

        cvss      = 0.0
        severity  = "low"
        cve_id    = "none"
        vuln_desc = "none"
        for v in vuln_scoring:
            if v.get("host", v.get("ip")) == ip:
                cvss      = v.get("predicted_score")
                severity  = v.get("severity")
                cve_id    = v.get("cve_id")
                vuln_desc = v.get("summary")

        dashboard_data.append({
            "id":                       str(i),
            "ip":                       ip,
            "severity":                 severity,
            "description":              description,
            "deviceType":               deviceType,
            "hostname":                 hostname,
            "cvss":                     cvss,
            "cve":                      cve_id,
            "vulnerability_description": vuln_desc,
            "status":                   status,
        })
        i += 1

    topology = build_topology(parsed_network or {}, discovered_hosts)

    return {"hosts": dashboard_data, "topology": topology, "vulns": vuln_scoring}