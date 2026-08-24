# llm config — LOCAL model (Ollama). This is the offline fallback used when the
# OpenRouter credits run out, not the primary path.
#
# gpt-oss:20b was the old default and CANNOT run on the 8 GB M2 Mac mini
# (~12-13 GB at MXFP4). qwen3:4b is ~2.5 GB at Q4_K_M, which fits alongside
# Postgres + the backend + Next.js. Keep thinking mode OFF — "timeout" below is
# 60s and a reasoning trace on this hardware blows straight through it.
MODEL_CONFIG = {
    "model_name": "qwen3:4b",
    "temperature": 0,
    "timeout": 60,
    "determinism": 1
}

# llm config — analysis tier (OpenRouter). recon_analysis, os_analysis,
# vuln_agent, reporter. This is where the report quality comes from.
#
# Was z-ai/glm-5 ($0.60/$1.92 per Mtok) — that costs ~$51 for 400 scheduled runs
# against a $42.63 balance, i.e. over budget. glm-4.7 ($0.40/$1.75) lands at
# ~$35/400 runs. Re-check pricing before changing; it moves.
ANALYSIS_MODEL_CONFIG = {
    "model_name": "z-ai/glm-4.7",
    "temperature": 0,
    "timeout": 300,
}

# llm config — fast tier when ONLINE (OpenRouter). recon_agent and
# data_formatting_agent only emit/reshape JSON, so they don't need the analysis
# model's price. glm-4.7-flash is $0.06/$0.40 per Mtok, ~7x cheaper in, ~4x out.
FAST_ONLINE_MODEL_CONFIG = {
    "model_name": "z-ai/glm-4.7-flash",
    "temperature": 0,
    "timeout": 60,
}

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# nmap scanning constants
TIMEOUT_VAL = 3600

# file/directory constants
SCANNING_DUMP_LOG = "./log/scan_dumps.txt"
SCAN_RESULTS_DIR = "./scan_results"
VULN_CLASSIFICATION_TRAINING_DATA = "./data/merged_cve.csv"

# logging constants
LOG_FILENAME = "./log/surge_log.log"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s/%(funcName)s >> %(message)s"

# recon agent constant
RECON_CONVERGENCE = {
    "max_iterations": 5,
    "max_no_change_iterations": 4,  # Increased from 3  
    "time_budget_seconds": 7200  # Increased to 2 hours from 33 min
}

# sanitization constants (used in /governance)
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
            "--version-trace", "--osscan-guess",
            # Scripting / vulnerability detection
            "--script", "--script-args", "--script-trace", "--script=banner,os-fingerprint", "--script=banner",
            # Safe, common vuln script sets
            "vuln",
            # Output
            "-oX", "-oN", "-oG", "-oA", "--reason",
            # Performance
            "--max-retries", "--min-rate", "--max-rate",
            "--host-timeout", "--packet-trace", "-Pn",
            # Networking
            "--traceroute", "--send-eth", "--send-ip", "-6", "2"
        },
        "max_port_range": 65535,
        "max_runtime_s": 5400,  # 90 min upper bound
        "allow_service_detection": True,
    },
}
    
METACHARACTERS = (";", "&", "|", "`", "$(", "$", "||")