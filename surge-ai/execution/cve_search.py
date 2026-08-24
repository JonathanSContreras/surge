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
        if response.status_code != 200:
            return []

        data = response.json()

        # New CIRCL API format: {"results": {"fkie_nvd": [[id, cve_dict], ...], ...}}
        results_map = data.get("results", {})

        # Prefer fkie_nvd (most complete NVD mirror), fall back to nvd or cvelistv5
        entries = (
            results_map.get("fkie_nvd")
            or results_map.get("nvd")
            or results_map.get("cvelistv5")
            or []
        )

        cves = []
        for entry in entries[:10]:
            _, cve_dict = entry
            cve_id = cve_dict.get("id", "")
            summary = ""
            for desc in cve_dict.get("descriptions", []):
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")
                    break
            if cve_id:
                cves.append({"id": cve_id, "summary": summary})

        return cves

    except Exception as e:
        return []