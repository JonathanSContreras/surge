from core.state import AgentState
from core.llm import get_llm
from config.constants import SCANNING_DUMP_LOG, RECON_CONVERGENCE, TIMEOUT_VAL
from agents.prompts import RECON_AGENT_SYSTEM_PROMPT
from execution.json_extract import extract_json
from execution.nmap_scanner import nmap_scanning
from execution.xml_parser import xml_parse, all_xml_output_to_txt
from config.logging_config import get_logger

from langchain.schema import AIMessage, SystemMessage, HumanMessage
import time
import json

# call global log file
logger = get_logger(__name__)

# RECON AGENT #
def recon(state: AgentState) -> AgentState:
    """
    Progressive recon loop that calls nmap commands to map out the full network. 
    Identifies open ports, devices, etc.
    Repeat until stop condition is met or no new hosts are found.
    """
    logger.info("Recon agent started")

    ## STATE INITIALIZATION
    state.setdefault("recon_seen_hosts", set())
    state.setdefault("recon_seen_ports", set())
    state.setdefault("recon_seen_services", set())
    state.setdefault("recon_no_change_count", 0)
    state.setdefault("recon_start_time", time.time())

    # --- VARIABLES ---
    discovered_hosts = state["recon_seen_hosts"]
    aggregated_logs = []
    cumulative_network = {}  # merged {ip: host_dict} across all iterations
    iteration = 0

    with open(SCANNING_DUMP_LOG, "a") as file:
        file.write(f"STARTING RECON AGENT:\n----------------\nmax iterations = {RECON_CONVERGENCE['max_iterations']}\nmax no change iterations = {RECON_CONVERGENCE['max_no_change_iterations']}\ntime budget (s): {RECON_CONVERGENCE['time_budget_seconds']}")

    # --- MAIN RECON LOOP ---   
    # define the llm     
    llm = get_llm()
    while True:
        iteration += 1
        # HARD CONVERGENCE
        if (iteration > RECON_CONVERGENCE["max_iterations"]
            or state["recon_no_change_count"] >= RECON_CONVERGENCE["max_no_change_iterations"]
            or time.time() - state["recon_start_time"] > RECON_CONVERGENCE["time_budget_seconds"]):
            logger.debug("Hard recon convergence reached, stopping RECON AGENT.")
            break

        # write to scan dump file
        logger.debug(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")  # sanity logging
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\n--- ITERATION {iteration} [{time.strftime('%Y-%m-%d %H:%M:%S')}] ---")
        ####

        # LLM DECISIONS
        if state["recon_no_change_count"] >= 2:
            logger.info("No new data last iteartion (skipping LLM escalation).")
            continue

        # prompt LLM to ensure correct output
        llm_input = f"""
        You are an autonomous network reconnaissance specialist.
        You MUST use the previous scan_type when responding unless explicitly changing strategy.
        You MUST produce only JSON in the specified schema, no explanations, code fences, or extra text.

        ### Context summary
        - Known hosts discovered so far: {len(discovered_hosts)}
        - Total scan iterations completed: {len(aggregated_logs)}
        - Active targets under analysis: {', '.join(state['targets'])}
        - Last scan_type: {state['scan_type']}


        ### Adaptive Scanning Rules
        1. **Low scans**: Host discovery only (`-sn`). Use for new subnets or fallback scans.
        2. **Medium scans**: Targeted port/service enumeration (`-sS`, `-sV`, `-O`). Collect banners, OS info, and light scripts (`-sC`).
        3. **High scans**: Aggressive, deep scans (`-A`, `--script vuln`, `-O`, `-sV`, full port range). Collect all metadata, vulnerability info, and OS fingerprints.

        - Escalate automatically if new hosts or services are discovered and metadata is incomplete.
        - Switch strategies automatically if no new hosts or open ports are found after 2 iterations.
        - Always prefer narrow incremental scans first, and avoid repeating the same scan on unchanged hosts.
        - Adjust timing (`-T`), port ranges (`-p`, `--top-ports`), and protocols (`-sS`, `-sU`) according to scan_type.
        - When in high scans, always include at least one vuln script (`--script vuln` or other default nmap scripts) and metadata flags (`-O`, `--traceroute`, `--reason`).

        ### Output Requirements
        - `flags`: nmap flags appropriate to scan_type
        - `targets`: hosts or CIDRs to focus on
        - `scan_type`: maintain current scan_type unless escalating
        - `reason`: concise rationale for this scan decision
        - `max_runtime_s`: upper limit for scan duration, based on the flags you provide give a resonable amount of time to scan
        - `escalation`: "none", "service_scan", or "deep_scan"

        ### JSON Schema Example
        {{
        "flags": [string],
        "targets": [string],
        "scan_type": "{state['scan_type']}",
        "reason": "string",
        "max_runtime_s": int,
        "escalation": "none" | "service_scan" | "deep_scan"
        }}

        Respond **only** with valid JSON matching this schema.
        """

        # ask LLM for scan descision (gpt oss needs it in a chat message list form)
        raw_decision: AIMessage = llm.invoke([
            SystemMessage(content=RECON_AGENT_SYSTEM_PROMPT),
            HumanMessage(content=json.dumps(llm_input))
        ])

        # write to scan dump file
        raw_text = getattr(raw_decision, "content", str(raw_decision))
        # print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        with open(SCANNING_DUMP_LOG, "a") as file:
            logger.info("WRITING TO DUMP LOG in sam_oss.py")
            file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] LLM raw output:\n{raw_text}")
        ####

        # extract json (json = LLM response/output)
        decision = extract_json(raw_text, iteration)
        logger.debug(f"Decision (at iter: {iteration} after prompt is {decision}")
        if not isinstance(decision, dict):
            decision = {}


        # --- ROBUST CHECK: fallback and reprompt LLM if the JSON is not found
        if not decision:
            # write to scan dump file
            logger.info(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON,skipping iteartion...")
            with open(SCANNING_DUMP_LOG, "a") as file:
                file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] No valid JSON, skipping iteration...")
            ####

            state["recon_no_change_count"] += 1
            continue

        # validate decision fields for nmap scan (have robust data type structure)
        flags = decision.get("flags", [])
        dec_targets = decision.get("targets", [])

        if not flags or not dec_targets:
            logger.info(f"~DECISION MISSING FLAGS OR TARGETS: flags={flags}, targets={dec_targets}")
            state["recon_no_change_count"] += 1
            continue

        # Ensure --traceroute is always included for medium/high scans regardless of LLM output.
        # This guarantees hop data in nmap XML for topology graph construction.
        current_scan_type = decision.get("scan_type", state["scan_type"])
        if current_scan_type in ("medium", "high") and "--traceroute" not in flags:
            flags = flags + ["--traceroute"]

        # EFFICIENCY GUARD: for medium/high scans, restrict targets to already-discovered IPs.
        # This prevents the LLM from re-scanning broad CIDR ranges after the initial discovery pass,
        # which generates hundreds of ghost "up" entries for IPs that never responded.
        if current_scan_type != "low" and discovered_hosts:
            narrowed = [t for t in dec_targets if t in discovered_hosts]
            if len(narrowed) < len(dec_targets):
                removed = set(dec_targets) - set(narrowed)
                logger.warning(f"Target narrowing: removed {removed} (not in discovered_hosts). Using {narrowed or list(discovered_hosts)}")
            dec_targets = narrowed if narrowed else list(discovered_hosts)

        # run validated nmap scan
        logger.debug(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running Nmap scan: {dec_targets} with flags {flags}")

        # write to scan dump file
        with open(SCANNING_DUMP_LOG, "a") as file:
            file.write(f"\nDecision fields have been validated. [{time.strftime('%Y-%m-%d %H:%M:%S')}]\tRunning Nmap scan on {dec_targets} with flags: {flags}.")
        ####

        # RUN NMAP
        log = nmap_scanning.invoke({
            "scan_type": decision.get("scan_type", state["scan_type"]),
            "flags": flags,
            "targets": dec_targets,
            # "timeout": min(max_runtime, TIMEOUT_VAL)  # THE max_runtime VALUE THE AGENT IS GIVING IS TO SMALL (making all in-depth scans have timed out)
            "timeout": TIMEOUT_VAL
        })
        aggregated_logs.append(log)
        logger.info(f"nmap scan finished with flags {flags} and appended to aggregated_logs")
        logger.debug(f".xml file saved to {log['xml_dir']}/{log['xml_file']}")

        # parse nmap scan output (will parse xml file to dictionary)  THIS IS AN ISSUE (the xml content is now the folder name)
        parsed = {}
        if log.get("success"):
            parsed = xml_parse(f"{log['xml_dir']}/{log['xml_file']}")  # NOTE: might need to concate the folder name and file name

        # merge into cumulative network (deduplicates by IP, newer data wins)
        cumulative_network.update(parsed)

        # DELTA DETECTION
        new_hosts = set(parsed.keys()) - discovered_hosts
        new_ports = set()
        new_services = set()

        for host, host_data in parsed.items():
            for svc in host_data.get("services", []):
                port_id = f"{host}:{svc.get('port')}"
                svc_id = f"{svc.get('product')}:{svc.get('version')}"

                if port_id not in state["recon_seen_ports"]:
                    new_ports.add(port_id)

                if svc_id not in state["recon_seen_services"]:
                    new_services.add(svc_id)

        # UPDATE STATE + CONVERGENCE
        if new_hosts or new_ports or new_services:
            logger.debug(
                f"New discovery — hosts:{len(new_hosts)} "
                f"ports:{len(new_ports)} services:{len(new_services)}"
            )
            discovered_hosts.update(new_hosts)
            state["recon_seen_ports"].update(new_ports)
            state["recon_seen_services"].update(new_services)
            state["recon_no_change_count"] = 0
        else:
            logger.info("No new hosts, ports, or services.")
            state["recon_no_change_count"] += 1

        # UPDATE AGENT STATE
        state["recon_results"] = {
            "last_log": log,
            "parsed_network": cumulative_network,
            "all_logs": aggregated_logs,
            "discovered_hosts": list(discovered_hosts),
            "iteration": iteration,
        }

        time.sleep(1)

    # FINAL XML AGGREGATION
    xml_dirs = [
        log["xml_dir"]
        for log in state["recon_results"]["all_logs"]
        if log.get("success") and log.get("xml_dir")
    ]

    if xml_dirs:
        xml_content_path = all_xml_output_to_txt(xml_dirs[0])
        with open(xml_content_path, "r", encoding="utf-8") as f:
            state["all_xml_content"] += f.read()

    logger.info("Recon agent finished cleanly.")
    return state