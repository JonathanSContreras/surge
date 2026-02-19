from core.state import AgentState
from governance.xgboost_data_cleaning import xgboost_data_cleaning
from execution.cvss_regessor_model import cvss_regressor
from config.logging_config import get_logger

import pandas as pd

# call global log file
logger = get_logger(__name__)

def cvss_scoring(state: AgentState) -> AgentState:
    """
    Calls the XGBoost classifier model and outputs the vulnerability with its label.
    """
    # get vulnerability findings
    vuln_list = state.get("vuln_normalized_results", [])  

    if not vuln_list:
        state["vuln_scoring"] = []
        logger.info("Vulnerability list is empty.")
        return state

    logger.debug(f"Received {len(vuln_list)} vulnerabilities to score")

    # create dataframe of vulnerability findings
    df = pd.DataFrame(vuln_list)
    print("df", df.head(), type(df))  # DID NOT PRINT

    # normalize categorical columns
    catgy_cols = ["access_authentication", "access_complexity", "access_vector", "impact_availability", "impact_confidentiality", "impact_integrity"]

    # # uppercase all categorical columns
    # for col in catgy_cols:
    #     if col in df.columns:
    #         df[col] = df[col].astype(str).str.upper()
    
    cve_data = xgboost_data_cleaning(df, catgy_cols)

    logger.info("Successfully cleaned scanned CVE data.")
    logger.debug(f"CVE Data shape: {cve_data.shape}")
    cve_data.to_csv("cvs_data_debug.csv", index=False)

    # will need to take the formatted data and output a score
    vulnerability_scores= cvss_regressor(cve_data)

    # get scored back to original data
    results = []
    for vuln, score in zip(vuln_list, vulnerability_scores):
        results.append({**vuln, "predicted_score": score})
        
    state["vuln_scoring"] = results

    ## OUTPUT VULN SCORING IN TXT FOR NOW TO TEST DASHBOARD PAYLOAD
    with open("vuln_scoring.txt", "w+") as f:
        f.write(str(results))
    ####

    logger.info("CVSS scoring agent has completed running and the state is updated.")

    return state
