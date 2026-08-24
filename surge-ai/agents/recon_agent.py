from core.state import AgentState
from core.llm import get_llm
from config.constants import SCANNING_DUMP_LOG, RECON_CONVERGENCE, TIMEOUT_VAL
from agents.prompts import RECON_AGENT_SYSTEM_PROMPT
from execution.json_extract import extract_json
from execution.nmap_scanner import nmap_scanning
from execution.xml_parser import xml_parse, all_xml_output_to_txt
from config.logging_config import get_logger
from api.activity import emit_activity_sync

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
    emit_activity_sync("Recon agent running — scanning network", agent_node="recon")

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
            logger.info("No new data last iteration (skipping LLM escalation).")
            state["recon_no_change_count"] += 1
            continue

        # prompt LLM to ensure correct output
        # NOTE ON THIS PROMPT (rewritten): the previous version told the model
        # "MUST use the previous scan_type unless explicitly changing strategy"
        # and then immediately handed it an "Adaptive Scanning Rules" block that
        # pushed aggressive escalation. Those two fight, and which one wins
        # depends on the model: a 4B dropped medium -> low with `-sn` while
        # still claiming escalation="service_scan"; a 7B jumped medium -> high
        # with `--script=vuln` on iteration 2, which is the path that turns Deep
        # scans into 3-5 hour runs. Replaced with one ordered decision ladder so
        # the tier is a function of observed state, not of model temperament.
        llm_input = f"""
        You are an autonomous network reconnaissance specialist deciding the NEXT nmap scan.

        ### Observed state
        - Iteration: {iteration} of {RECON_CONVERGENCE['max_iterations']}
        - Current scan_type: {state['scan_type']}
        - Hosts discovered so far: {len(discovered_hosts)}
        - Open ports seen so far: {len(state['recon_seen_ports'])}
        - Services identified so far: {len(state['recon_seen_services'])}
        - Consecutive iterations with no new findings: {state['recon_no_change_count']}
        - Targets: {', '.join(state['targets'])}

        ### Decision ladder — evaluate IN ORDER, use the FIRST rule that matches
        1. Hosts discovered == 0
           -> scan_type "low", flags ["-sn","-T4"], escalation "none"
              (Find out what is alive before doing anything else.)
        2. Hosts discovered > 0 AND services identified == 0
           -> scan_type "medium", escalation "service_scan"
              flags: ["-sS","-sV","-O","--top-ports","1000","-T4"]
              (Enumerate what is listening on the hosts you already found.)
        3. Services identified > 0 AND no-new-findings count == 0
           -> scan_type "medium", escalation "none"
              Narrow the scan: target only hosts with incomplete data, widen
              ports (e.g. ["-sS","-sV","--top-ports","4000","-T4"]).
        4. Services identified > 0 AND no-new-findings count >= 1
           -> scan_type "high", escalation "deep_scan"
              flags: ["-sS","-sV","-O","--script=vuln","-T4"]
              (Breadth is exhausted; only now is a vuln-script pass justified.)

        ### Hard constraints
        - scan_type and escalation MUST agree:
            escalation "none"          -> scan_type is unchanged from Current
            escalation "service_scan"  -> scan_type MUST be "medium"
            escalation "deep_scan"     -> scan_type MUST be "high"
        - NEVER lower scan_type. "{state['scan_type']}" is a floor, not a suggestion.
          low -> medium -> high only. Going back down is always wrong.
        - Do NOT use "-sn" unless rule 1 matched. "-sn" skips ports entirely, so
          emitting it at medium or high throws away the whole iteration.
        - Use "--script=vuln" ONLY under rule 4, and only once. It is the single
          most expensive thing you can request.
        - Multi-token flags must be separate list items: ["--top-ports","1000"],
          never ["--top-ports 1000"]. Value-style flags use "=": "--script=vuln".
        - max_runtime_s ceilings by tier: low 180, medium 1200, high 5400.
          Anything above the ceiling for your chosen scan_type is rejected.

        ### JSON Schema
        {{
        "flags": [string],
        "targets": [string],
        "scan_type": "low" | "medium" | "high",
        "reason": "string — name the rule number you applied",
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

        # For high/deep scans, force the aggressive flags the LLM might omit.
        # Without these, "deep" scan degrades silently to a light port scan.
        if current_scan_type == "high":
            # Full port range — LLM tends to pick --top-ports instead
            if "-p-" not in flags and not any(f.startswith("-p") for f in flags):
                flags = flags + ["-p-"]
            # Vuln scripts — the whole point of a deep scan
            has_script = any("--script" in f for f in flags)
            if not has_script:
                flags = flags + ["--script", "vuln"]
            # Service + OS detection
            if "-sV" not in flags:
                flags = flags + ["-sV"]
            if "-O" not in flags:
                flags = flags + ["-O"]

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

        # Emit escalation/de-escalation event if scan type changed
        scan_order = {"low": 0, "medium": 1, "high": 2, "deep": 3}
        prev_scan_type = state.get("scan_type", "low")
        if current_scan_type != prev_scan_type:
            direction = (
                "Escalating" if scan_order.get(current_scan_type, 0) > scan_order.get(prev_scan_type, 0)
                else "De-escalating"
            )
            emit_activity_sync(
                f"{direction} to {current_scan_type} scan",
                event_type="info",
                agent_node="recon",
                detail=decision.get("reason"),
            )
            state["scan_type"] = current_scan_type

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

            # Emit discovery delta
            parts = []
            if new_hosts:
                parts.append(f"{len(new_hosts)} new host{'s' if len(new_hosts) != 1 else ''}")
            if new_ports:
                parts.append(f"{len(new_ports)} new port{'s' if len(new_ports) != 1 else ''}")
            if new_services:
                parts.append(f"{len(new_services)} new service{'s' if len(new_services) != 1 else ''}")
            emit_activity_sync(
                f"Discovered {', '.join(parts)}",
                event_type="info",
                agent_node="recon",
                detail=decision.get("reason"),
            )
        else:
            logger.info("No new hosts, ports, or services.")
            state["recon_no_change_count"] += 1
            if state["recon_no_change_count"] >= 2:
                emit_activity_sync(
                    "No new data — holding scan strategy",
                    event_type="info",
                    agent_node="recon",
                )

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

    host_count = len(state.get("recon_results", {}).get("discovered_hosts", []))
    emit_activity_sync(
        f"Recon complete — {host_count} host{'s' if host_count != 1 else ''} discovered across {iteration} iteration{'s' if iteration != 1 else ''}",
        event_type="success",
        agent_node="recon",
    )
    logger.info("Recon agent finished cleanly.")
    return state