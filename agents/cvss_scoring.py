from core.state import AgentState
from governance.cve_data_cleaning import xgboost_data_cleaning
from execution.cvss_scorer import cvss_scorer
from config.logging_config import get_logger

import pandas as pd

# call global log file
logger = get_logger(__name__)

def cvss_scoring(state: AgentState) -> AgentState:
    """
    Calls the XGBoost classifier model and outputs the vulnerability with its label.
    """

    vuln_list = state.get("vuln_formatted_results", [])  # list object
    if not vuln_list or len(vuln_list) == 0:
        state["vuln_scoring"] = []
        logger.info("Vulnerability list is empty.")
        return state

    logger.debug(f"vuln_list contains: {vuln_list}")
    for vuln_data in vuln_list:
        cwe = vuln_data.get("cwe_code")
        cwe_name = vuln_data.get("cwe_name")
        summary = vuln_data.get("summary")
        access_auth = vuln_data.get("access_authentication").upper()
        access_complex = vuln_data.get("access_complexity").upper()
        access_vec = vuln_data.get("access_vector").upper()
        impa_avail = vuln_data.get("impact_availability").upper()
        impa_confid = vuln_data.get("impact_confidentiality").upper()
        impa_integ = vuln_data.get("impact_integrity").upper()

        vuln_df = pd.DataFrame([{
                "cwe_code": cwe if cwe is not None else 0, 
                "cwe_name": cwe_name, 
                "summary": summary, 
                "access_authentication": access_auth,
                "access_complexity": access_complex, 
                "access_vector": access_vec, 
                "impact_availability": impa_avail, 
                "impact_confidentiality": impa_confid, 
                "impact_integrity": impa_integ
            }])
        catgy_cols = ["access_authentication", "access_complexity", "access_vector", "impact_availability", "impact_confidentiality", "impact_integrity"]
        cve_data = xgboost_data_cleaning(vuln_df, catgy_cols)

        logger.info("Successfully cleaned scanned CVE data.")
        logger.debug(f"CVE Data shape: {cve_data.shape}")
        cve_data.to_csv("cvs_data_debug.csv", index=False)

        # will need to take the formatted data and output a score
        vulnerability_score = cvss_scorer(cve_data)

        logger.debug(f"CVSS Scorer Outputted -> a score of: {vulnerability_score}")

        state["vuln_scoring"] = vulnerability_score

    logger.info("CVSS scoring agent has completed running and the state is updated.")

    return state
