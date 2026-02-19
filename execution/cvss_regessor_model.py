# imports
import xgboost as xgb

## GLOBAL CACHES ##
XGB_MODEL = xgb.Booster()
XGB_MODEL.load_model("model/xgb_regressor.json")

def cvss_regressor(prediction_vals):
    """
    Pulls a trained XGBoost model and uses the CVE-formatted data that the Vulnerability Agent found to create/predict CVSS scores for each vulnerability.
    
    Args
        prediction_vals: 
    """
    print("prediction_vals", prediction_vals)
    
    dmatrix = xgb.DMatrix(prediction_vals)
    predictions = XGB_MODEL.predict(dmatrix)
    print(f"Prediction score: {predictions}")

    return predictions