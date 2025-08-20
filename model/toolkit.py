"""
@author: Brianna Hinds
Description: Defines all nmap scans SAM can do, its toolkit.
"""
# TODO
# make better/clear docstrings (when/why) explaining when to use each method
# provide context to SAM in the prompt so SAM knows to follow pentest methodology
# store prior scan results in memory so it doesnt re run the same scan unnecessarily
# after running make sure the output is useable for the parser
# after running log the actions into a database

from langchain.tools import tool
import subprocess  # allows for command execution and easy integration with metasploit

# NMAP HELPER FUNCTION
def run_nmap(cmd, scan):
    """
    Helper function to run the nmap commands from SAMs defined toolkit.
    Returns the results from the scan.

    ARGS    
        cmd: List object of the nmap command.
        scan: String definition of the scan type, used in result metadata.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": " ".join(cmd),
            "scan_type": scan,
            "xml": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "scan_type": scan, 
            "xml": "",
            "stderr": "Scan timed out.",
            "success": False
        }
    
@tool
def ping_sweep(target:str) -> dict:
    """
    Scan all live hosts on a target network using a ping sweep.
    Example: "192.168.1.0/24"
    """
    return run_nmap(["nmap", "-sn", "-oX", "-", target], "ping sweep")


@tool
def port_scan_stealth(target:str) -> dict:
    """
    Find all open ports on a target with minimal detection via stealth SYN scan.
    Use this when you need to discover open ports on a host *without being easily detected*. 
    Good first step before aggressive scans.
    """
    return run_nmap(["nmap", "-sS", "-p-", "-oX", "-", target], "stealth port scan")

@tool
def port_scan_decoy(target:str) -> dict:
    """
    Find all open ports on a target with minimal detection by deploying a decoy scan.
    """
    return run_nmap(["nmap", "-sS", "-D", "RND:10", "-oX", "-", target], "decoy port scan")

@tool
def port_scan_aggressive(target:str) -> dict:
    """
    Aggressively scan all ports on a target by pulling OS and service detection.
    """
    return run_nmap(["nmap", "-A", "-oX", "-", target], "aggressive port scan")

@tool
def service_enum(target:str) -> dict:
    """
    Get service banners on a target.
    """
    return run_nmap(["nmap", "-sV", "-oX", "-", target], "get service banners")

@tool
def os_fingerprint(target:str) -> dict:
    """
    Identify a target's OS.
    """
    return run_nmap(["nmap", "-O", "-oX", "-",  target], "os scan")

@tool
def vuln_scan(target:str) -> dict:
    """
    Check known vulnerabilities on a target.
    """
    return run_nmap(["nmap", "--script", "vuln", "-oX", "-", target], "vulnerability scan")

@tool
def pseudo_exploit(target:str):
    return f"Simulated exploit attempt on {target} -> success!"