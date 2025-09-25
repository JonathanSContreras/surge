TIMEOUT_VAL = 300
LOG_FILE = "../utils/scan_history.json"
SANITIZATION_TIER_CONFIG= {
    "low": {  # only host discovery
        "allowed_flags": {"-sn", "-T0", "-T1", "-T2", "-T3", "-T4"},
        "max_port_range": 0,   # 0 indicates "no port scans allowed"
        "max_runtime_s": 120,
        "allow_service_detection": False,
    },
    "medium": {  # limited port/sreeevice scans
        "allowed_flags": {"-sn", "-sS", "-sT", "-sV", "-Pn", "-T0", "-T1", "-T2", "-T3"},
        "max_port_range": 1024,  # allow ports up to 1-1024 (or lists of ports within that)
        "max_runtime_s": 300,
        "allow_service_detection": True,
    },
    "high": {  # "critical" / admin-approved — wide permissions
        "allowed_flags": {
            "-sn", "-sS", "-sT", "-sU", "-sV", "-O", "-Pn",
            "-T0", "-T1", "-T2", "-T3", "-T4", "-p"  # -p treated specially
        },
        "max_port_range": 65535,
        "max_runtime_s": 1800,
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")