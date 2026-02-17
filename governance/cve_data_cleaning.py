# imports
import pandas as pd
from sentence_transformers import SentenceTransformer
import json
import joblib

## GLOBAL CACHES ##
SBERT_MODEL = SentenceTransformer("all-MiniLM-L6-v2")

# load feature schema
with open("./model/feature_schema.json", "r") as f:
    EXPECTED_FEATURES = json.load(f)["features"]

# load pre-fitted encoders
OHE_ENCODER = joblib.load("./model/ohe_encoder.pkl")
TFIDF_ENCODER = joblib.load("./model/tfidf_encoder.pkl")

def align_features_to_xgb_model(df, expected_features):
    """
    Ensure dataframe has exact same columns as model expects, in same order.
    
    Args:
        df: Current feature dataframe
        expected_features: List of feature names from training
    
    Returns:
        Aligned dataframe with missing columns added (as 0) and extra columns removed
    """
    print(f"[align_features_to_model] Input has {len(df.columns)} columns")
    print(f"[align_features_to_model] Expected {len(expected_features)} columns")
    
    # Add missing columns with 0 values
    missing_cols = set(expected_features) - set(df.columns)
    if missing_cols:
        print(f"[align_features_to_model] Adding {len(missing_cols)} missing columns")
        print(f"[align_features_to_model] Missing columns (first 10): {list(missing_cols)[:10]}")
        for col in missing_cols:
            df[col] = 0
    
    # Remove extra columns not in training
    extra_cols = set(df.columns) - set(expected_features)
    if extra_cols:
        print(f"[align_features_to_model] Removing {len(extra_cols)} extra columns")
        print(f"[align_features_to_model] Extra columns: {list(extra_cols)}")
        df = df.drop(columns=list(extra_cols))
    
    # Reorder columns to match training
    df = df[expected_features]
    
    print(f"[align_features_to_model] Final shape: {df.shape}")
    return df

def xgboost_data_cleaning(df:pd.DataFrame, catgy_cols:list, summary_col="summary") -> pd.DataFrame:
    """
    Responsible for formatting the found vulnerabilities within the scanned network into a format that the XGBoost model can understand.
    
    Args
        df: DataFrame of Vulnerability Agent's findings
        catgy_cols: type list of different categories
        summary_col: column that houses the encoded summary based on the Sentence Transformer evaluation
    """
    cve_data = df.copy()

    # debugging prints
    print(f"[xgboost_data_cleaning] Input shape: {df.shape}")
    print(f"[xgboost_data_cleaning] Input columns: {df.columns}")

    # make sure cwe_code column exists
    if "cwe" in cve_data.colymns and "cwe_code" not in cve_data.columns:
        cve_data.rename(columns={"cwe": "cwe_code"}, inplace=True)
        print("[xgboost_data_cleaning] Renamed 'cwe' to 'cwe_code'")

    # fill na categorical columns as "UNKNOWN"
    for col in catgy_cols:
        if col in cve_data.columns:
            cve_data[col] = cve_data[col].fillna("UNKNOWN")
            cve_data[col] = cve_data[col].astype(str).upper()

    # one hot encode categorical columns from prefitted model
    catgy_encode = OHE_ENCODER.fit_transform(cve_data[catgy_cols])

    # combine data
    cve_data = pd.concat([cve_data.drop(columns=catgy_cols), catgy_encode], axis=1)

    # vectorize summary field (SBERT)
    # model = SentenceTransformer("all-MiniLM-L6-v2") 
    embeddings = SBERT_MODEL.encode(cve_data[summary_col].tolist())
    embeddings_df = pd.DataFrame(
        embeddings,
        columns=[f"SBERT_summary_{i}" for i in range(embeddings.shape[1])]
    )

    merged_cve_data = pd.concat([cve_data.drop(columns=[summary_col]), embeddings_df], axis=1)

    # vectorize cve name field from prefitted TFIDF vectorizer
    cwe_name_feat = TFIDF_ENCODER.fit_transform(cve_data["cwe_name"])
    name_feat_df = pd.DataFrame(
        cwe_name_feat.toarray(),
        columns=[f"tfidf_name_{i}" for i in range(cwe_name_feat.shape[1])]
    )

    # combine data
    merged_cve_data = pd.concat([merged_cve_data.drop(columns=["cwe_name"]), name_feat_df], axis=1)
    
    # align features to match trained XGBoost model schema
    merged_cve_data = align_features_to_xgb_model(merged_cve_data, EXPECTED_FEATURES)

    return merged_cve_data
