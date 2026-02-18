from workflow.runner import run_workflow

def execute_workflow(scan_type: str, targets: list[str]) -> dict:

    # initial_state = {
    #     "scan_type": scan_type,
    #     "targets": targets,
    #     "recon": {},
    #     "vulnerability": {},
    #     "analysis": {},
    #     "report": {},
    # }

    initial_state = {
        # "scan_type": "high",
        # "targets": ["10.10.160.0/24"],  # whole subnet scan  HCUEngg ["10.10.162.0/24"], Apt ["192.168.1.0/24"]
        "scan_type": scan_type,
        "targets": targets,
        "recon_results": {},
        "all_xml_content": "",
        "recon_analysis": "",
        "os_fingerprint_results": {},
        "os_xml_content": "",
        "os_analysis": "",
        "vuln_raw_results": [],
        "vuln_normalized_results": [],
        "vuln_scoring": {},
        "network_findings": ""
    }

    return run_workflow(initial_state)