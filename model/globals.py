TIMEOUT_VAL = 300
LOG_FILE = "./utils/scan_history.txt"
SCANNING_DUMP_LOG = "./utils/scan_dumps.txt"
SANITIZATION_TIER_CONFIG= {
    "low": {  # only host discovery
        "allowed_flags": {"-sn", "-T0", "-T1", "-T2", "-T3", "-T4", "-Pn"},
        "max_port_range": 0,   # 0 indicates "no port scans allowed"
        "max_runtime_s": 120,
        "allow_service_detection": False,
    },
    "medium": {  # limited port/service scans
        "allowed_flags": {
            "-sn", "-sS", "-sT", "-sV", "-Pn",  # discovery & TCP scans
            "-T0", "-T1", "-T2", "-T3", "-T4",  # timing templates
            "-p",  # limited port scans
            "--open", "--top-ports",            # focus on open/top ports
            "-oX", "-oN", "-oG",                 # output formats
        },        
        "max_port_range": 1024,  # allow ports up to 1-1024 (or lists of ports within that)
        "max_runtime_s": 300,
        "allow_service_detection": True,
    },
    "high": {  # "critical" / admin-approved — wide permissions
        "allowed_flags": {
            "-sn", "-sS", "-sT", "-sU", "-sV", "-O", "-A", "-Pn",  # full TCP/UDP + OS + Aggressive
            "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",               # full timing range
            "-p", "--open", "--top-ports", "--exclude", "--exclude-ports",
            "-oX", "-oN", "-oG", "-oA",                             # all output formats
            "--max-retries", "--min-rate", "--max-rate", "--host-timeout",
            "--packet-trace", "--reason", "--script"                # optional advanced options
        },
        "max_port_range": 65535,
        "max_runtime_s": 1800,
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")