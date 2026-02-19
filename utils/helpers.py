"""
@author: Brianna Hinds
Description: Helper functions for the agents.
"""
from config.constants import SCAN_RESULTS_DIR

import datetime
import re
import os

def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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

## --- XML PARSING HELPER FUNCTIONS --- #
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


## --- DASHBOARD DATA CONVERSION HELPER FUNCTIONS --- ##
def score_conversion(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 5.0:
        return "medium"
    else:
        return "low"