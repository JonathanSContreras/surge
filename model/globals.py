TIMEOUT_VAL = 300
SCANNING_DUMP_LOG = "./utils/scan_dumps.txt"
SANITIZATION_TIER_CONFIG= {
    "low": {  # only host discovery
        "allowed_flags": {"-sn", "-T0", "-T1", "-T2", "-T3", "-T4", "-Pn"},
        "max_port_range": 0,   # 0 indicates "no port scans allowed"
        "max_runtime_s": 180,
        "allow_service_detection": False,
    },
    "medium": {  # limited port/service scans
        "allowed_flags": {
            "-sn", "-sS", "-sT", "-sV", "-Pn", "-sU",  # light UDP 
            "-sC",  # default safe scripts
            "-T0", "-T1", "-T2", "-T3", "-T4",  # timing templates
            "-p", "--open", "--top-ports",  # limited port scans and focusing
            "--version-intensity", "--version-all", "--version-light",  # version servicing tuning
            "--osscan-guess", "--traceroute", "-O",  # OS/traceroute
            "-oX", "-oN", "-oG",                 # output formats
            "--reason", "--dns-servers", "--send-ip", "-6"  # safe options

        },        
        "max_port_range": 4096,  # allow ports up to 1-1024 (or lists of ports within that)
        "max_runtime_s": 900,
        "allow_service_detection": True,
    },
    "high": {  # "critical" / admin-approved — wide permissions
        "allowed_flags": {
            # scan types
            "-sn", "-sS", "-sT", "-sU", "-sV", "-O", "-A", "-Pn",
            "-sC",
            # timing
            "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
            # ports and excluding
            "-p", "--open", "--top-ports", "--exclude", "--exclude-ports",
            # version/service tuning
            "--version-intensity", "--version-all", "--version-light",
            # scripts & advanced
            "--script", "--script-args", "--script-trace", "vuln",
            # outputs
            "-oX", "-oN", "-oG", "-oA",
            # performance tuning
            "--max-retries", "--min-rate", "--max-rate", "--host-timeout",
            "--packet-trace", "--reason", "--data-length", "--mtu",
            # traceroute / network helpers
            "--traceroute", "--send-eth", "--send-ip", "-6",
            # other useful flags
            "--version-trace", "--version-all",
        },
        "max_port_range": 65535,
        "max_runtime_s": 5400,
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")