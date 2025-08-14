"""
@author: Brianna Hinds
Description: Defines all nmap scans SAM can do, its toolkit.
"""
# TODO
# make better/clear docstrings explaining when to use each method
# provide context to SAM in the prompt so SAM knows to follow pentest methodology
# store prior scan results in memory so it doesnt re run the same scan unnecessarily

from langchain.tools import tool
import nmap
import subprocess  # allows for command execution and easy integration with metasploit

nm = nmap.PortScanner()

@tool
def ping_sweep(target:str) -> dict:
    """
    Scan all live hosts on a target network using a ping sweep.
    Example: "192.168.1.0/24"
    """
    cmd = ["nmap", "-sn", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def port_scan_stealth(target:str) -> dict:
    """
    Find all open ports on a target with minimal detection via stealth SYN scan.
    """
    cmd = ["nmap", "-sS", "-p-", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def port_scan_decoy(target:str) -> dict:
    """
    Find all open ports on a target with minimal detection by deploying a decoy scan.
    """
    cmd = ["nmap", "-sS", "-D", "RND:10", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def port_scan_aggressive(target:str) -> dict:
    """
    Aggressively scan all ports on a target by pulling OS and service detection.
    """
    cmd = ["nmap", "-A", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def service_enum(target:str) -> dict:
    """
    Get service banners on a target.
    """
    cmd = ["nmap", "-sV", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def os_fingerprint(target:str) -> dict:
    """
    Identify a target's OS.
    """
    cmd = ["nmap", "-O", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def vuln_scan(target:str) -> dict:
    """
    Check known vulnerabilities on a target.
    """
    cmd = ["nmap", "--script", "vuln", target]
    try: 
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=100
        )
        return {
            "command": "".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "Scan timed out.",
            "success": False
        }

@tool
def custom_exploit(target):
    """
    CUSTOM EXPLOIT VIA METASPLOIT
    """
    pass