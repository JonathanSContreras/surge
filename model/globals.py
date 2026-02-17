TIMEOUT_VAL = 3600
SCANNING_DUMP_LOG = "./utils/scan_dumps.txt"
SCAN_RESULTS_DIR = "./scan_results"
VULN_CLASSIFICATION_TRAINING_DATA = "./data/merged_cve.csv"
# RECON_CONVERGENCE = {
#     "max_iterations": 5,
#     "max_no_change_iterations": 3,
#     "time_budget_seconds": 2000
# }
RECON_CONVERGENCE = {
    "max_iterations": 10,  # Increased from 5
    "max_no_change_iterations": 4,  # Increased from 3  
    "time_budget_seconds": 7200  # Increased to 2 hours from 33 min
}
SANITIZATION_TIER_CONFIG = {
    "low": {  # Host discovery only
        "allowed_flags": {
            "-sn", "-T0", "-T1", "-T2", "-T3", "-T4", "-Pn"
        },
        "max_port_range": 0,
        "max_runtime_s": 180,
        "allow_service_detection": False,
    },

    "medium": {  # Version & light vuln scanning
        "allowed_flags": {
            # Scan types
            "-sS", "-sT", "-sU", "-sV", "-sC", "-Pn",
            # Timing & performance
            "-T0", "-T1", "-T2", "-T3", "-T4",
            "--max-retries", "--min-rate", "--max-rate",
            # Port selection
            "-p", "--open", "--top-ports",
            # Version & OS detection
            "--version-intensity", "--version-all", "--version-light",
            "-O", "--osscan-guess",
            # Basic NSE scripting for vuln detection
            "--script", "--script-args",
            # Output formats
            "-oX", "-oN", "-oG", "--reason",
            # Network helpers
            "--traceroute", "--send-ip", "--dns-servers",
        },
        "max_port_range": 4096,      # Allow up to top 4096 ports
        "max_runtime_s": 1200,       # 20 minutes
        "allow_service_detection": True,
    },

    "high": {  # Full administrative recon + vuln enumeration
        "allowed_flags": {
            # Scan types
            "-sS", "-sT", "-sU", "-sV", "-A", "-O", "-Pn", "-sC",
            # Timing
            "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
            # Ports
            "-p", "--open", "--top-ports", "--exclude", "--exclude-ports",
            # Version & OS
            "--version-intensity", "--version-all", "--version-light",
            "--version-trace", "--osscan-guess"
            # Scripting / vulnerability detection
            "--script", "--script-args", "--script-trace", "--script=banner,os-fingerprint"
            # Safe, common vuln script sets
            "vuln",
            # Output
            "-oX", "-oN", "-oG", "-oA", "--reason",
            # Performance
            "--max-retries", "--min-rate", "--max-rate",
            "--host-timeout", "--packet-trace", "-Pn"
            # Networking
            "--traceroute", "--send-eth", "--send-ip", "-6",
        },
        "max_port_range": 65535,
        "max_runtime_s": 5400,  # 90 min upper bound
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")