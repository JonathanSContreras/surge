from typing import TypedDict

# data structure class build for the CVE entry data
class CVEEntry(TypedDict, total=False):
    cve_id: str
    mod_date: str
    pub_date: str
    cvss: float
    cwe_code: str
    cwe_name: str
    summary: str
    access_authentication: str
    access_complexity: str
    access_vector: str
    impact_availability: str
    impact_confidentiality: str
    impact_integrity: str