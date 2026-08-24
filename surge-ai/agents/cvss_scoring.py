from core.state import AgentState
from governance.xgboost_data_cleaning import xgboost_data_cleaning
from execution.cvss_regessor_model import cvss_regressor
from config.logging_config import get_logger
from agents.dashboard_payload import dashboard_data_grab
from api.activity import emit_activity_sync

import pandas as pd
import json

# call global log file
logger = get_logger(__name__)

def cvss_scoring(state: AgentState) -> AgentState:
    """
    Calls the XGBoost classifier model and outputs the vulnerability with its label.
    """
    emit_activity_sync("Scoring vulnerabilities with ML model", event_type="warning", agent_node="cvss_scoring")
    # get vulnerability findings
    vuln_list = state.get("vuln_normalized_results", [])

    if not vuln_list:
        logger.info("Vulnerability list is empty.")

        # run the dashboard data creation
        recon = state.get("recon_results", {})
        discovered_hosts  = recon.get("discovered_hosts", [])
        parsed_network    = recon.get("parsed_network", {})
        dashboard_data = dashboard_data_grab([], discovered_hosts=discovered_hosts, parsed_network=parsed_network)

        ## OUTPUT DASHBOARD DATA TO HAVE DATA FOR JONATHAN
        json_string = json.dumps(dashboard_data, indent=4)
        with open(f"{state['run_dir']}/dashboard_data.json", "w+") as f:
            f.write(json_string)
        ####

        return {"vuln_scoring": [], "topology": dashboard_data["topology"]}

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
        results.append({**vuln, "predicted_score": float(score)})
        
    state["vuln_scoring"] = results

    run_dir = state["run_dir"]

    ## OUTPUT VULN SCORING IN TXT FOR NOW TO TEST DASHBOARD PAYLOAD
    with open(f"{run_dir}/vuln_scoring.txt", "w+") as f:
        f.write(str(results))
    ####

    # after the scoring run the dashboard data build method
    recon = state.get("recon_results", {})
    discovered_hosts  = recon.get("discovered_hosts", [])
    parsed_network    = recon.get("parsed_network", {})
    dashboard_data = dashboard_data_grab(state["vuln_scoring"], discovered_hosts=discovered_hosts, parsed_network=parsed_network)
    state["topology"] = dashboard_data["topology"]

    ## OUTPUT DASHBOARD DATA TO HAVE DATA FOR JONATHAN
    json_string = json.dumps(dashboard_data, indent=4)

    with open(f"{run_dir}/dashboard_data.json", "w+") as f:
        f.write(json_string)
    ####

    emit_activity_sync(
        f"CVSS scoring complete — {len(results)} vulnerabilit{'ies' if len(results) != 1 else 'y'} scored",
        event_type="success",
        agent_node="cvss_scoring",
    )
    logger.info("CVSS scoring agent has completed running and the state is updated.")

    return {"vuln_scoring": results, "topology": dashboard_data["topology"]}
