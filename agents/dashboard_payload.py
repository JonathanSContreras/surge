from utils.helpers import score_conversion
from config.logging_config import get_logger

from typing import Any
import os

"""
NOTES:
- I personally want this file to call xml_parser.py for all xml outputs to build dictionaries per xml file
- WILL NEED TO have a .xml output for the os fingerprint scan
- merge all the dictionaries where the key is the IP address
"""
# define global log file
logger = get_logger(__name__)

def network_dict_build(xml_path: str) -> dict:
    # NOTE: get all xml files and parse it into a dictionary, return the dictionary
    pass

# NOTE: do I even need to input the state?
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

ID -> can be auto generated
IP -> pull from dictionaries
SEVERITY -> from score conversion
DESCRIPTION -> can come from summary of parse
"""
def build_dashboard_payload() -> list[dict[str, Any]]:
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
        for root, dir, files in os.walk(xml_dir, topdown=True):  # root -> ./scan_results, files = list of all files in folder
            for filename in files:
                # only parse .xml files
                if filename.endswith(".xml"):
                    logger.info(f"Parsing {filename} in dir: {root}")

                    # create the full file path
                    file_to_parse = os.path.join(root, filename)

                    # call the parser



                

    
    pass