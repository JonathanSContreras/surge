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
import time
import datetime

# NMAP HELPER FUNCTION
def run_nmap(cmd, scan):
    """
    Helper function to run the nmap commands from SAMs defined toolkit.
    Returns the results from the scan.

    ARGS    
        cmd: List object of the nmap command.
        scan: String definition of the scan type, used in result metadata.
    """
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "timestamp": datetime.datetime.now(),
            "target": cmd[-1],
            "command": " ".join(cmd),
            "scan_type": scan,
            "xml": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
            "process_time": round(time.time()-start, 2)
        }
    except subprocess.TimeoutExpired:
        return {
            "timestamp": datetime.datetime.now(),
            "target": cmd[-1],
            "command": " ".join(cmd),
            "scan_type": scan, 
            "xml": "",
            "stderr": "Scan timed out.",
            "success": False,
            "process_time": round(time.time()-start, 2)
        }
        
@tool
def ping_sweep(target:str) -> dict:
    """
    Discover live hosts in a target network using an ICMP ping sweep.
    
    WHEN TO USE:
        - As the very first step in reconnaissance.
        - When you need to identify which hosts in a subnet are up.
    
    INPUT:
        - A network range or subnet (e.g., "192.168.1.0/24").
    
    OUTPUT:
        - Raw Nmap XML with metadata (host discovery results).
    """
    return run_nmap(["nmap", "-sn", "-oX", "-", target], "ping sweep")


@tool
def port_scan_stealth(target:str) -> dict:
    """
    Perform a stealth SYN scan to discover open ports on a host with reduced chance of detection.
    
    WHEN TO USE:
        - After identifying a live host.
        - When you want to enumerate open ports quietly before deeper scans.
    
    INPUT:
        - A single host IP or hostname (e.g., "192.168.1.10").
    
    OUTPUT:
        - Raw Nmap XML showing open ports and service states.
    """
    return run_nmap(["nmap", "-sS", "-p-", "-oX", "-", target], "stealth port scan")

@tool
def port_scan_decoy(target:str) -> dict:
    """
    Perform a SYN scan using decoys to hide the true origin of the scan.
    
    WHEN TO USE:
        - When stealth is critical and you want to confuse IDS/IPS or logs.
        - Typically after confirming the target is live.
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - Raw Nmap XML of open ports (with decoy traffic).
    """
    return run_nmap(["nmap", "-sS", "-D", "RND:10", "-oX", "-", target], "decoy port scan")

@tool
def port_scan_aggressive(target:str) -> dict:
    """
    Run an aggressive scan including OS detection, service versions, and traceroute.
    
    WHEN TO USE:
        - After initial port scans confirm the target is live and responsive.
        - When you want detailed host/service fingerprinting.
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - Raw Nmap XML including open ports, service versions, OS guesses, and traceroute.
    """
    return run_nmap(["nmap", "-A", "-oX", "-", target], "aggressive port scan")

@tool
def service_enum(target:str) -> dict:
    """
    Enumerate running services and grab banners on open ports.
    
    WHEN TO USE:
        - After discovering open ports on a host.
        - To gather service information for vulnerability mapping.
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - Raw Nmap XML with service versions and banners.
    """
    return run_nmap(["nmap", "-sV", "-oX", "-", target], "get service banners")

@tool
def os_fingerprint(target:str) -> dict:
    """
    Attempt to identify the target's operating system using TCP/IP stack fingerprinting.
    
    WHEN TO USE:
        - After confirming a host is alive.
        - To help prioritize exploits or payloads based on OS type.
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - Raw Nmap XML with OS guesses and accuracy scores.
    """
    return run_nmap(["nmap", "-O", "-oX", "-",  target], "os scan")

@tool
def vuln_scan(target:str) -> dict:
    """
    Run Nmap's built-in vulnerability detection scripts against the target.
    
    WHEN TO USE:
        - After service enumeration.
        - To quickly check for known vulnerabilities (NSE vuln scripts).
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - Raw Nmap XML including vulnerability findings.
    """
    return run_nmap(["nmap", "--script", "vuln", "-oX", "-", target], "vulnerability scan")

@tool
def pseudo_exploit(target:str):
    """
    Simulate an exploit attempt against the target.
    
    WHEN TO USE:
        - After detecting a vulnerability with a high CVSS score.
        - For training/testing purposes (no real exploitation is performed).
    
    INPUT:
        - A single host IP or hostname.
    
    OUTPUT:
        - A string message indicating a simulated success/failure.
    """
    return f"Simulated exploit attempt on {target} -> success!"