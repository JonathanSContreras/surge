from langchain.tools import tool
import requests

## --- VULNERABILITY TOOLS --- ##   NEED TO GET MORE INFO THROUG RECON: socket library, portscanner library, banner grabs (https://medium.com/offensive-security-walk-throughs/creating-a-vulnerability-scanner-in-python-b5b59817b38d)
@tool
def cve_search(product: str, vendor: str="") -> list:
    """Fetch top 5 CVE's for a given product from CIRCL."""

    # construct CVE API url
    if vendor:
        url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    else: # no vendor given
        url = f"https://cve.circl.lu/api/search/{product}"

    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            print("cve_search", data)
            return [
                {"id": item["id"], "summary": item["summary"]}
                for item in data.get("data", [])[:10]
            ]        
        return {"data": [], "error": f"Failed to fetch CVEs for {product}"}

    except Exception as e:
        return {"error": str(e)}