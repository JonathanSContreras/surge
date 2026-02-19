from utils.helpers import score_conversion
from config.logging_config import get_logger
from execution.xml_parser import xml_parse

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
"""
def derive_xml_data() -> list[dict[str, Any]]:
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


## MAIN
if __name__ == "__main__":
    lst = derive_xml_data()

    print(len(lst))

    with open("lst.txt", "w+", encoding="utf-8") as f:
        f.write(str(lst))