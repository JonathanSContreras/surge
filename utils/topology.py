"""
utils/topology.py

Builds a network topology graph (nodes + links) from parsed_network data.

Two algorithms:
  - Traced-path: uses nmap --traceroute hop data when available (ground truth)
  - Subnet-fallback: infers connectivity from /24 subnets + MAC vendor heuristics
    when traceroute data is absent

Output is a plain dict (no networkx dependency) suitable for JSON serialization.
"""

import ipaddress
from config.logging_config import get_logger

logger = get_logger(__name__)

# MAC vendor substrings that indicate router/firewall/switch hardware
_GATEWAY_VENDORS = {
    "cisco", "juniper", "palo alto", "fortinet", "netgear", "linksys",
    "tp-link", "ubiquiti", "mikrotik", "aruba", "zyxel", "d-link",
    "sonicwall", "watchguard", "sophos", "checkpoint",
}

_GATEWAY_DEVICE_TYPES = {"router", "firewall", "switch", "WAP"}

_SERVER_PORTS      = {21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443, 8888, 27017}
_ROUTER_PORTS      = {23, 161, 162, 179, 520, 521}   # telnet, SNMP, BGP, RIP
_IOT_PORTS         = {1883, 8883, 5683}               # MQTT, CoAP
_SERVER_VENDORS    = {"vmware", "xen", "qemu", "amazon", "microsoft azure", "proxmox"}
_WORKSTATION_VENDORS = {"apple", "intel nuc", "dell", "lenovo", "hewlett", "microsoft surface"}
_IOT_VENDORS       = {"raspberry pi", "espressif", "arduino", "particle", "tuya"}


def _infer_device_type(ip: str, host: dict) -> str | None:
    """Infer device type from MAC vendor, open ports, and hostname when nmap has no osclass."""
    vendor = (host.get("mac_vendor") or "").lower()

    if any(g in vendor for g in _GATEWAY_VENDORS):
        return "router"
    if any(v in vendor for v in _SERVER_VENDORS):
        return "server"
    if any(v in vendor for v in _WORKSTATION_VENDORS):
        return "workstation"
    if any(v in vendor for v in _IOT_VENDORS):
        return "iot"

    services = host.get("services") or []
    open_ports = {
        int(s["port"]) for s in services
        if s.get("state") == "open" and str(s.get("port", "")).isdigit()
    }
    if open_ports & _ROUTER_PORTS:
        return "router"
    if open_ports & _SERVER_PORTS:
        return "server"
    if open_ports & _IOT_PORTS:
        return "iot"

    hostnames = host.get("hostnames") or []
    label = (hostnames[0] if hostnames else "").lower()
    for kw, dtype in [
        ({"router", "gateway", "gw", "rtr", "fw", "firewall"}, "router"),
        ({"switch", "sw-", "-sw"}, "switch"),
        ({"server", "srv", "db", "web", "mail", "smtp", "api"}, "server"),
    ]:
        if any(k in label for k in kw):
            return dtype

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_from_host(ip: str, host: dict, intermediate: bool = False) -> dict:
    os_info = host.get("os") or {}
    services = host.get("services") or []
    open_count = sum(1 for s in services if s.get("state") == "open")
    hostnames = host.get("hostnames") or []
    label = hostnames[0] if hostnames else ip

    return {
        "id":           ip,
        "ip":           ip,
        "label":        label,
        "nodeType":     "host",          # refined later
        "deviceType":   os_info.get("device_type") or _infer_device_type(ip, host),
        "mac_vendor":   host.get("mac_vendor"),
        "os":           os_info.get("name"),
        "status":       host.get("status", "unknown"),
        "isIntermediate": intermediate,
        "services":     open_count,
    }


def _scanner_node() -> dict:
    return {
        "id":           "scanner",
        "ip":           None,
        "label":        "Scanner",
        "nodeType":     "scanner",
        "deviceType":   None,
        "mac_vendor":   None,
        "os":           None,
        "status":       "up",
        "isIntermediate": False,
        "services":     0,
    }


def _subnet_node(net: str) -> dict:
    return {
        "id":           f"subnet:{net}",
        "ip":           None,
        "label":        net,
        "nodeType":     "subnet",
        "deviceType":   "subnet",
        "mac_vendor":   None,
        "os":           None,
        "status":       "up",
        "isIntermediate": True,
        "services":     0,
    }


def _is_gateway_candidate(ip: str, host: dict) -> bool:
    """Heuristic: is this host likely a gateway/router?"""
    os_info = host.get("os") or {}
    device_type = (os_info.get("device_type") or "").lower()
    if device_type in {d.lower() for d in _GATEWAY_DEVICE_TYPES}:
        return True

    vendor = (host.get("mac_vendor") or "").lower()
    if any(gv in vendor for gv in _GATEWAY_VENDORS):
        return True

    # Conventional .1 address for its subnet
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        if ipaddress.ip_address(ip) == net.network_address + 1:
            return True
    except ValueError:
        pass

    return False


# ---------------------------------------------------------------------------
# Traced-path algorithm
# ---------------------------------------------------------------------------

def _build_traced_topology(
    parsed_network: dict,
    host_ips: set,
) -> tuple[dict, list]:
    """
    Build nodes and links from traceroute hop data.
    Returns (nodes_by_id, links_set) where links_set contains (source, target) tuples.
    """
    nodes: dict[str, dict] = {"scanner": _scanner_node()}
    link_set: set[tuple[str, str]] = set()

    # Count how often each IP appears at TTL=1 (to identify gateway)
    ttl1_count: dict[str, int] = {}
    # Count how often each IP appears at TTL>=2 across multiple hosts (routers)
    ttl2plus_count: dict[str, int] = {}

    for ip, host in parsed_network.items():
        if ip not in host_ips:
            continue
        trace = host.get("trace")
        if not trace or not trace.get("hops"):
            continue

        hops = trace["hops"]

        # Build the full path: scanner → hop[0] → hop[1] → ... → target
        path = ["scanner"] + [h["ip"] for h in hops if h["ip"]] + [ip]

        # Deduplicate consecutive identical IPs (edge case)
        deduped = [path[0]]
        for node in path[1:]:
            if node != deduped[-1]:
                deduped.append(node)

        # Emit edges
        for i in range(len(deduped) - 1):
            link_set.add((deduped[i], deduped[i + 1]))

        # Register intermediate hop nodes (not the target itself)
        for hop in hops:
            hop_ip = hop["ip"]
            if hop_ip is None:
                continue
            # Only count as router candidate if this hop is NOT the target host itself.
            # For single-hop same-subnet traces the only hop IS the target — don't classify it as router.
            if hop_ip != ip:
                ttl = hop.get("ttl") or 0
                if ttl == 1:
                    ttl1_count[hop_ip] = ttl1_count.get(hop_ip, 0) + 1
                elif ttl >= 2:
                    ttl2plus_count[hop_ip] = ttl2plus_count.get(hop_ip, 0) + 1

            if hop_ip not in nodes:
                if hop_ip in parsed_network:
                    nodes[hop_ip] = _node_from_host(hop_ip, parsed_network[hop_ip], intermediate=False)
                else:
                    # Intermediate-only node (router not directly scanned)
                    nodes[hop_ip] = {
                        "id":           hop_ip,
                        "ip":           hop_ip,
                        "label":        hop.get("host") or hop_ip,
                        "nodeType":     "router",
                        "deviceType":   None,
                        "mac_vendor":   None,
                        "os":           None,
                        "status":       "up",
                        "isIntermediate": True,
                        "services":     0,
                    }

        # Register target node
        if ip not in nodes:
            nodes[ip] = _node_from_host(ip, host)

    # Classify node types based on hop frequency
    total_traced = sum(
        1 for h in parsed_network.values()
        if h.get("trace") and h["trace"].get("hops")
    )
    threshold = max(1, total_traced * 0.5)

    gateway_ip = None
    for ip, count in ttl1_count.items():
        if count >= threshold:
            if ip in nodes:
                nodes[ip]["nodeType"] = "gateway"
            if gateway_ip is None:
                gateway_ip = ip
        else:
            # Below threshold — it's an intermediate router but not the main gateway
            if ip in nodes and nodes[ip]["nodeType"] == "host":
                nodes[ip]["nodeType"] = "router"

    for ip in ttl2plus_count:
        if ip in nodes and nodes[ip]["nodeType"] == "host":
            nodes[ip]["nodeType"] = "router"

    # Add any discovered hosts that had no trace data (connect directly to gateway or scanner)
    for ip in host_ips:
        if ip not in nodes and ip in parsed_network:
            nodes[ip] = _node_from_host(ip, parsed_network[ip])
            anchor = gateway_ip if gateway_ip else "scanner"
            link_set.add((anchor, ip))

    return nodes, list(link_set), gateway_ip


# ---------------------------------------------------------------------------
# Subnet-fallback algorithm
# ---------------------------------------------------------------------------

def _build_fallback_topology(
    parsed_network: dict,
    host_ips: set,
) -> tuple[dict, list, str | None]:
    """
    Infer topology from /24 subnet grouping and gateway heuristics.
    Used when no traceroute data is available.
    Emits virtual subnet nodes so the graph shows: scanner → subnet → hosts.
    """
    nodes: dict[str, dict] = {"scanner": _scanner_node()}
    link_set: set[tuple[str, str]] = set()
    gateway_ip: str | None = None

    # Group hosts by /24
    subnets: dict[str, list[str]] = {}
    for ip in host_ips:
        if ip not in parsed_network:
            continue
        try:
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            net = "unknown"
        subnets.setdefault(net, []).append(ip)

    for net, ips in subnets.items():
        subnet_id = f"subnet:{net}"
        nodes[subnet_id] = _subnet_node(net)
        link_set.add(("scanner", subnet_id))

        subnet_gateway = None
        for ip in ips:
            if _is_gateway_candidate(ip, parsed_network[ip]):
                subnet_gateway = ip
                break

        for ip in ips:
            nodes[ip] = _node_from_host(ip, parsed_network[ip])
            link_set.add((subnet_id, ip))

        if subnet_gateway:
            nodes[subnet_gateway]["nodeType"] = "gateway"
            if gateway_ip is None:
                gateway_ip = subnet_gateway

    return nodes, list(link_set), gateway_ip


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_topology(
    parsed_network: dict,
    discovered_hosts: list | set | None = None,
) -> dict:
    """
    Build a topology graph from parsed_network data.

    Args:
        parsed_network: {ip: host_dict} from recon_results
        discovered_hosts: confirmed host IPs (whitelist); if None, uses all keys

    Returns:
        {
            "nodes": [...],
            "links": [{"source": str, "target": str, "type": "traced"|"inferred"}],
            "metadata": {
                "total_nodes": int,
                "total_links": int,
                "has_trace_data": bool,
                "gateway_ip": str | None,
            }
        }
    """
    if not parsed_network:
        return {
            "nodes": [_scanner_node()],
            "links": [],
            "metadata": {"total_nodes": 1, "total_links": 0, "has_trace_data": False, "gateway_ip": None},
        }

    if discovered_hosts is not None:
        host_ips = set(discovered_hosts) & set(parsed_network.keys())
    else:
        host_ips = set(parsed_network.keys())

    # Check if any host has usable trace data
    has_trace = any(
        parsed_network[ip].get("trace") and parsed_network[ip]["trace"].get("hops")
        for ip in host_ips
    )

    if has_trace:
        logger.info("topology: using traceroute data for %d hosts", len(host_ips))
        nodes, raw_links, gateway_ip = _build_traced_topology(parsed_network, host_ips)
        link_type = "traced"
    else:
        logger.info("topology: no traceroute data — falling back to subnet inference for %d hosts", len(host_ips))
        nodes, raw_links, gateway_ip = _build_fallback_topology(parsed_network, host_ips)
        link_type = "inferred"

    links = [{"source": s, "target": t, "type": link_type} for s, t in raw_links]

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "metadata": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "has_trace_data": has_trace,
            "gateway_ip": gateway_ip,
        },
    }
