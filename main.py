"""
Entrypoint for Surge Project
"""

from core.orchestration import execute_workflow
from config.logging_config import setup_logging, get_logger
from config.constants import SCANNING_DUMP_LOG, LOG_FILENAME
from execution.address_grab import build_initial_target_lists

import time

# call global log file
logger = get_logger(__name__)

if __name__ == "__main__":
    # define the logging setup
    setup_logging()

    # empty scanning log dump file and workflow log file
    with open(SCANNING_DUMP_LOG, "w"):
        pass
    with open(LOG_FILENAME, "w"):
        pass

    # define start time
    start = time.perf_counter()

    # scan_type = "high"
    # targets = ["10.10.160.0/24", "10.10.161.0/24", "10.10.162.0/24", "10.10.163.0/24"]  # whole subnet scan  HCUEngg ["10.10.162.0/24"], Apt ["192.168.1.0/24"], ["10.10.160.0/12"]
    initial = build_initial_target_lists()
    scan_type = initial["scan_type"]
    targets = initial["targets"]

    final_state = execute_workflow(scan_type, targets)

    ## DEBUG TXT PRINT
    with open("final_state_result.json", "w+") as f:
        f.write(str(final_state))
    ####
    
    # logging prints
    time_in_minutes = (time.perf_counter()-start) / 60
    logger.info(f"Code finished in {time_in_minutes} minutes.") 


