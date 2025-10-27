"""
@author: Brianna Hinds
Description: Tool method definitions for Surge MAS.
"""
# imports
from langchain.tools import tool
import subprocess
import datetime
import time
import shlex
from helper import sanitize_flags_for_tier, store_xml_to_folder
from globals import TIMEOUT_VAL, VULN_CLASSIFICATION_TRAINING_DATA
import requests
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBRegressor
from sklearn.model_selection import train_test_split

## --- RECON METHOD/TOOLS --- ##
@tool
def nmap_scanning(scan_type: str, flags: list[str], targets: list[str], timeout: int = TIMEOUT_VAL) -> dict:
    """
    Run an nmap scan in a safe, tiered manner.

    Returns JSON only. Structure:
    {
        "timestamp": ISO timestamp,
        "command": [...],
        "targets": [...],
        "xml_dir": xml_folder_path as a string,
        "xml_file": xml file just created as a string
        "stderr": "...",
        "returncode": 0,
        "success": true/false,
        "max_runtime_s": float
    }

    The LLM must not output human-readable messages, only JSON.
    """

    # import logging, subprocess, shlex, time, datetime

    # logging.basicConfig(level=logging.DEBUG)
    # logger = logging.getLogger("NMAP_SCANNER")

    ## --- ROBUST CHECKS --- ##
    # check flags content
    if not isinstance(flags, list):
        return {"error": "flags must be a list"}

    # check the target list content
    if not isinstance(targets, list) or len(targets) == 0:
        return {"error": "targets must be a non-empty list"}

    flags_flat = []
    for f in flags:
        flags_flat.extend(shlex.split(f))  # split commands like "-p1-1024" vs multi tokens
    ## --------- ##

    ## --- SANITIZATION --- ##
    sanitized = sanitize_flags_for_tier(flags_flat, scan_type)
    if isinstance(sanitized, dict) and "error" in sanitized:
        return sanitized  # return the error directly
    
    flags_flat = sanitized

    # scan variables
    cmd = ["nmap"] + flags_flat + targets
    start_time = time.time()
    timestamp = datetime.datetime.now().isoformat() + "Z"
    # logger.debug("Running command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        
        # write the xml output to a .xml file store it in a folder
        safe_timestamp = timestamp.replace(":", "_").replace(".", "_")  # '2025-10-15T12-45-59-442649'
        file_path = f"{safe_timestamp}_nmap.xml"

        # ensure stdout is text
        xml_output = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8")

        # link that folder name to the "xml" key
        folder_path = store_xml_to_folder(targets, xml_output, file_path)

        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml_dir": folder_path,
            "xml_file": file_path,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        # log_history(log)
        return log
    except subprocess.TimeoutExpired:
        log = {
            "timestamp": timestamp,
            "command": cmd,
            "targets": targets,
            "xml_dir": None,
            "xml_file": None,
            "stderr": "~SCAN TIMED OUT",
            "returncode": None,
            "success": False,
            "max_runtime_s": round(time.time()-start_time, 2)
        }

        # add log
        # log_history(log)
        return log


## --- VULNERABILITY TOOLS --- ##   NEED TO GET MORE INFO THROUG RECON: socket library, portscanner library, banner grabs (https://medium.com/offensive-security-walk-throughs/creating-a-vulnerability-scanner-in-python-b5b59817b38d)
@tool
def cve_search(product: str, vendor: str="") -> list:
    """Fetch top 5 CVE's for a given product from CIRCL."""

    base_url = f"https://cve.circl.lu/api/search/{product}"
    url = f"{base_url}/{vendor}/{product}" if vendor else f"{base_url}/{product}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return [
                {"id": item["id"], "summary": item["summary"]}
                for item in data.get("data", [])[:10]
            ]        
        return {"error": f"Failed to fetch CVEs for {product}"}

    except Exception as e:
        return {"error": str(e)}
        
@tool
def cve_identification():
    pass


## --- VULNERABILITY CLASSIFIER METHODS --- ##
def xgboost_data_cleaning(df, catgy_cols:list, summary_col:str):
    cve_data = df.copy()

    # fill na categorical columns as "UNKNOWN"
    catgy_cols = ["access_authentication", "access_complexity", "access_vector", "impact_availability", "impact_confidentiality", "impact_integrity"]
    cve_data[catgy_cols] = cve_data[catgy_cols].fillna("UNKNOWN")

    # one hot encode categorical columns
    ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False).set_output(transform="pandas")
    catgy_encode = ohe.fit_transform(cve_data[catgy_cols])

    # combine data
    cve_data = pd.concat([cve_data, catgy_encode], axis=1)
    cve_data.drop(columns=catgy_cols, inplace=True)

    # vectorize summary field (SBERT)
    model = SentenceTransformer("all-MiniLM-L6-v2") 
    embeddings = model.encode(cve_data[summary_col])
    embeddings_df = pd.DataFrame(
        embeddings,
        columns=[f"SBERT_summary_{i}" for i in range(embeddings.shape[1])]
    )

    merged_cve_data = pd.concat([cve_data.drop(columns=["summary"]), embeddings_df], axis=1)

    # vectorize cve name field
    tfidf_name = TfidfVectorizer(max_features=50, stop_words="english")
    cwe_name_feat = tfidf_name.fit_transform(cve_data["cwe_name"])
    name_feat_df = pd.DataFrame(
        cwe_name_feat.toarray(),
        columns=[f"tfidf_name_{i}" for i in range(cwe_name_feat.shape[1])]
    )

    # combine data
    merged_cve_data = pd.concat([cve_data.drop(columns=["cwe_name"]), name_feat_df], axis=1)
    merged_cve_data.head()

    # combine data
    merged_cve_data = pd.concat([cve_data.drop(columns=["cwe_name"]), name_feat_df], axis=1)
    # merged_cve_data.head()

    return merged_cve_data

def cvss_scorer(prediction_vals):
    testing_data = pd.read_csv(VULN_CLASSIFICATION_TRAINING_DATA)
    X = testing_data.drop(columns="cvss")
    X = X.select_dtypes(exclude="object")
    y = testing_data["cvss"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = XGBRegressor()
    model.fit(X_train, y_train)

    predict = model.predict(prediction_vals)
    print(f"Prediction score: {predict}")

    return predict
