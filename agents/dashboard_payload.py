from utils.helpers import score_conversion
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
def dashboard_data_grab(vuln_scoring:AgentState) -> list[dict]:
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
    # parse the xml data to get the xml data
    xml_data = _derive_xml_data()

    # initialize dashboard data list and id value
    dashboard_data = []
    i = 1 
    # for each key (ip) in the xml I want to grab its equivalent value in the vuln_scoring list of dictionaries
    for n in xml_data:
        for ip in n.keys():
        # for key in n.keys():
            # initiali dictionary 
            local_dict = {}

            id = str(i)
            ip = n[ip].get("ip")
            description = n[ip].get("description", "no description found")
            # ip = n[key].get("ip")
            # description = n[key].get("description", "no description found")
            deviceType = "idk"
            hostname = "idk"
            status = n[ip].get("status", "down")
            # status = n[key].get("status", "down")

            # go through the vulnerabilities data and see if the IP exists
            cvss = 0.0
            severity = "low"
            cve_id = "none"
            vuln_desc = "none"
            for v in vuln_scoring:
                if v["ip"] == ip:
                    cvss = v.get("predicted_score")
                    severity = v.get("severity")
                    cve_id = v.get("cve_id")
                    vuln_desc = v.get("description")

            # print(n)
            local_dict["id"] = id
            local_dict["ip"] = ip
            local_dict["severity"] = severity
            local_dict["description"] = description
            local_dict["deviceType"] = deviceType
            local_dict["hostname"] = hostname
            local_dict["cvss"] = cvss
            local_dict["cve"] = cve_id
            local_dict["vulnerability_description"] = vuln_desc
            local_dict["status"] = status

            # append the created dictionary to list
            dashboard_data.append(local_dict)

            # update i
            i += 1

    return dashboard_data 