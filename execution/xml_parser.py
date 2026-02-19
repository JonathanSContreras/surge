import os
import re
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_root(xml_data: str) -> ET.Element | None:
    """
    Return an ElementTree root from either a file path or raw XML string.
    Returns None on failure.
    """
    try:
        if os.path.exists(xml_data):
            return ET.parse(xml_data).getroot()

        s = xml_data.strip()
        if not s.startswith("<"):
            return None

        # Some nmap XML files chain multiple <nmaprun> blocks (concatenated scans).
        # Wrap in a synthetic root so ET can parse the whole thing at once.
        wrapped = f"<scans>{s}</scans>"
        return ET.fromstring(wrapped)

    except ET.ParseError:
        # Fallback: try to parse each <nmaprun> block individually
        return _parse_multi_root(xml_data)
    except Exception:
        return None


def _parse_multi_root(xml_data: str) -> ET.Element | None:
    """
    Split concatenated nmaprun blocks and assemble a synthetic root.
    """
    blocks = re.split(r"(?=<\?xml)", xml_data.strip())
    synthetic = ET.Element("scans")

    for block in blocks:
        block = block.strip()
        if not block:
            continue
        # Strip the XML declaration so ET can parse the fragment
        block = re.sub(r"<\?xml[^?]*\?>", "", block).strip()
        # Strip the XSL stylesheet PI
        block = re.sub(r"<\?xml-stylesheet[^?]*\?>", "", block).strip()
        if not block:
            continue
        try:
            node = ET.fromstring(block)
            synthetic.append(node)
        except ET.ParseError:
            continue

    return synthetic if len(synthetic) else None


def _extract_addresses(host: ET.Element) -> tuple[str | None, str | None, str | None]:
    """Return (ipv4_addr, mac_addr, mac_vendor) for a host element."""
    ipv4_addr = mac_addr = mac_vendor = None

    for addr_elem in host.findall("address"):
        addr = addr_elem.attrib.get("addr", "")
        addrtype = addr_elem.attrib.get("addrtype", "")

        if addrtype == "ipv4" and IPV4_PATTERN.match(addr):
            ipv4_addr = addr
        elif addrtype == "mac":
            mac_addr = addr
            mac_vendor = addr_elem.attrib.get("vendor") or None

    return ipv4_addr, mac_addr, mac_vendor


def _extract_hostnames(host: ET.Element) -> list[str]:
    return [
        h.attrib["name"]
        for h in host.findall("hostnames/hostname")
        if h.attrib.get("name")
    ]


def _extract_status(host: ET.Element) -> str:
    elem = host.find("status")
    return elem.attrib.get("state", "unknown") if elem is not None else "unknown"


def _extract_scripts(parent: ET.Element) -> dict[str, str]:
    """Collect all <script> children of *parent* into {id: output}."""
    return {
        s.attrib["id"]: s.attrib.get("output", "")
        for s in parent.findall("script")
        if s.attrib.get("id")
    }


def _extract_services(host: ET.Element) -> tuple[list[dict], dict[str, int]]:
    """
    Return (services_list, port_state_summary).

    port_state_summary counts how many ports are in each state bucket
    (open / closed / filtered / open|filtered) across both <port> entries
    and <extraports> summaries.
    """
    services: list[dict] = []
    state_summary: dict[str, int] = {}

    ports_elem = host.find("ports")
    if ports_elem is None:
        return services, state_summary

    # --- Bulk extra-ports (closed/filtered en masse) ---
    for ep in ports_elem.findall("extraports"):
        state = ep.attrib.get("state", "unknown")
        count = int(ep.attrib.get("count", 0))
        state_summary[state] = state_summary.get(state, 0) + count

    # --- Individual ports ---
    for port in ports_elem.findall("port"):
        port_data: dict = {
            "port":     port.attrib.get("portid"),
            "protocol": port.attrib.get("protocol"),
        }

        # State
        state_elem = port.find("state")
        if state_elem is not None:
            port_state = state_elem.attrib.get("state", "unknown")
            port_data.update({
                "state":      port_state,
                "reason":     state_elem.attrib.get("reason"),
                "reason_ttl": state_elem.attrib.get("reason_ttl"),
            })
            state_summary[port_state] = state_summary.get(port_state, 0) + 1
        else:
            port_data.update({"state": "unknown", "reason": None, "reason_ttl": None})

        # Service
        svc = port.find("service")
        if svc is not None:
            port_data.update({
                "service":   svc.attrib.get("name", "unknown"),
                "product":   svc.attrib.get("product"),
                "version":   svc.attrib.get("version"),
                "extrainfo": svc.attrib.get("extrainfo"),
                "ostype":    svc.attrib.get("ostype"),
                "tunnel":    svc.attrib.get("tunnel"),
                "method":    svc.attrib.get("method"),
                "conf":      svc.attrib.get("conf"),
                "cpe":       [c.text for c in svc.findall("cpe") if c.text],
            })
        else:
            port_data.update({
                "service": "unknown", "product": None, "version": None,
                "extrainfo": None, "ostype": None, "tunnel": None,
                "method": None, "conf": None, "cpe": [],
            })

        # Scripts attached to this port
        scripts = _extract_scripts(port)
        if scripts:
            port_data["scripts"] = scripts

        services.append(port_data)

    return services, state_summary


def _extract_os(host: ET.Element) -> dict:
    """
    Return a rich OS dictionary covering matches, classes, CPE,
    ports used for detection, and the raw fingerprint string.
    """
    os_elem = host.find("os")
    if os_elem is None:
        return {}

    matches = [
        {
            "name":     m.attrib.get("name"),
            "accuracy": int(m.attrib.get("accuracy", 0)),
        }
        for m in os_elem.findall("osmatch")
    ]

    classes = [
        {
            "type":      c.attrib.get("type"),
            "vendor":    c.attrib.get("vendor"),
            "osfamily":  c.attrib.get("osfamily"),
            "osgen":     c.attrib.get("osgen"),
            "accuracy":  int(c.attrib.get("accuracy", 0)),
            "cpe":       [cp.text for cp in c.findall("cpe") if cp.text],
        }
        for c in os_elem.findall(".//osclass")
    ]

    all_cpe = list({cp.text for cp in os_elem.findall(".//cpe") if cp.text})

    ports_used = [
        {
            "state":  pu.attrib.get("state"),
            "proto":  pu.attrib.get("proto"),
            "portid": pu.attrib.get("portid"),
        }
        for pu in os_elem.findall("portused")
    ]

    fp_elem = os_elem.find("osfingerprint")
    fingerprint = fp_elem.attrib.get("fingerprint", "") if fp_elem is not None else ""

    # Convenience top-level fields derived from best match
    best_match   = matches[0] if matches else {}
    best_class   = classes[0] if classes else {}

    return {
        "name":        best_match.get("name"),
        "accuracy":    best_match.get("accuracy", 0),
        "device_type": best_class.get("type"),
        "vendor":      best_class.get("vendor"),
        "osfamily":    best_class.get("osfamily"),
        "osgen":       best_class.get("osgen"),
        "cpe":         all_cpe,
        "matches":     matches,
        "classes":     classes,
        "ports_used":  ports_used,
        "fingerprint": fingerprint,
    }


def _extract_uptime(host: ET.Element) -> dict:
    elem = host.find("uptime")
    if elem is None:
        return {}
    return {
        "seconds":   elem.attrib.get("seconds"),
        "last_boot": elem.attrib.get("lastboot"),
    }


def _extract_distance(host: ET.Element) -> int | None:
    elem = host.find("distance")
    if elem is not None:
        try:
            return int(elem.attrib.get("value", ""))
        except ValueError:
            pass
    return None


def _extract_host_scripts(host: ET.Element) -> dict[str, str]:
    """Scripts attached directly to the host (not a port)."""
    hs_elem = host.find("hostscript")
    if hs_elem is None:
        return {}
    return _extract_scripts(hs_elem)


def _synthesize_description(
    os_info: dict,
    mac_vendor: str | None,
    services: list[dict],
) -> str:
    """
    Build a human-readable one-liner for the host, e.g.:
    'Apple iOS 15.x (phone) — AzureWave Technology NIC'
    Falls back gracefully when OS detection is ambiguous.
    """
    parts: list[str] = []

    if os_info.get("name"):
        parts.append(os_info["name"])
        if os_info.get("device_type"):
            parts[-1] += f" ({os_info['device_type']})"
    elif os_info.get("osfamily"):
        desc = os_info["osfamily"]
        if os_info.get("osgen"):
            desc += f" {os_info['osgen']}"
        parts.append(desc)

    if mac_vendor:
        parts.append(f"{mac_vendor} NIC")

    # Mention notable open services if no OS info at all
    if not parts:
        open_svcs = [
            s["service"] for s in services
            if s.get("state") == "open" and s.get("service") not in (None, "unknown")
        ]
        if open_svcs:
            parts.append("Services: " + ", ".join(dict.fromkeys(open_svcs)))

    return " — ".join(parts) if parts else "Unknown device"


def _process_host(host: ET.Element) -> tuple[str | None, dict]:
    """
    Parse a single <host> element and return (ipv4_key, host_dict).
    Returns (None, {}) if the host has no valid IPv4 address.
    """
    ipv4_addr, mac_addr, mac_vendor = _extract_addresses(host)
    if not ipv4_addr:
        return None, {}

    status   = _extract_status(host)
    hostnames = _extract_hostnames(host)
    services, port_state_summary = _extract_services(host)
    os_info  = _extract_os(host)
    uptime   = _extract_uptime(host)
    distance = _extract_distance(host)
    host_scripts = _extract_host_scripts(host)
    description  = _synthesize_description(os_info, mac_vendor, services)

    entry = {
        # Core identity
        "ip":          ipv4_addr,
        "status":      status,
        "description": description,
        "hostnames":   hostnames,
        "mac_address": mac_addr,
        "mac_vendor":  mac_vendor,
        "distance":    distance,

        # OS
        "os": os_info,

        # Ports / services
        "services":           services,
        "port_state_summary": port_state_summary,

        # Uptime
        "uptime": uptime,

        # Host-level NSE script output
        "host_scripts": host_scripts,
    }

    return ipv4_addr, entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def xml_parse(xml_data: str) -> dict:
    """
    Parse one or more concatenated Nmap XML outputs into a structured dict
    keyed by IPv4 address.

    Args:
        xml_data: File path to an .xml file OR a raw XML string
                  (including concatenated multi-scan strings).

    Returns:
        {
            "10.10.160.1": {
                "ip":          "10.10.160.1",
                "status":      "up",
                "description": "Palo Alto Networks firewall (firewall)",
                "hostnames":   [],
                "mac_address": "94:56:41:3E:D6:12",
                "mac_vendor":  "Palo Alto Networks",
                "distance":    1,
                "os": {
                    "name":        "...",
                    "accuracy":    91,
                    "device_type": "firewall",
                    "vendor":      "Palo Alto Networks",
                    "osfamily":    "...",
                    "osgen":       "...",
                    "cpe":         [...],
                    "matches":     [...],
                    "classes":     [...],
                    "ports_used":  [...],
                    "fingerprint": "...",
                },
                "services": [
                    {
                        "port":      "80",
                        "protocol":  "tcp",
                        "state":     "open",
                        "reason":    "syn-ack",
                        "reason_ttl":"64",
                        "service":   "http",
                        "product":   "...",
                        "version":   "...",
                        "extrainfo": "...",
                        "ostype":    "...",
                        "tunnel":    None,
                        "method":    "probed",
                        "conf":      "10",
                        "cpe":       [...],
                        "scripts":   {"http-title": "Login"},   # optional
                    },
                    ...
                ],
                "port_state_summary": {"open": 3, "closed": 997, "filtered": 0},
                "uptime": {"seconds": "33", "last_boot": "Wed Feb 18 ..."},
                "host_scripts": {"smb2-security-mode": "...", ...},
            },
            ...
        }

        On error returns: {"error": "<message>"}
    """
    if not xml_data:
        return {"error": "~EMPTY INPUT"}

    root = _parse_root(xml_data)
    if root is None:
        return {"error": "~FAILED TO PARSE XML"}

    network_config: dict = {}

    # Root may be our synthetic <scans> wrapper or a bare <nmaprun>
    # Collect all <host> elements regardless of nesting depth
    all_hosts = root.findall(".//host")

    for host in all_hosts:
        # Skip hosthint elements that appear as children of nmaprun
        # (they share the same tag but sit outside <host> blocks — .//host
        # won't capture them, but double-check parent isn't hosthint)
        ipv4_key, entry = _process_host(host)
        if not ipv4_key:
            continue

        # Merge strategy: if we've seen this IP before, prefer the entry
        # with more service detail (later/deeper scans tend to be richer).
        existing = network_config.get(ipv4_key)
        if existing is None:
            network_config[ipv4_key] = entry
        else:
            # Keep whichever has more open services; merge host_scripts
            if len(entry["services"]) >= len(existing["services"]):
                entry["host_scripts"] = {**existing["host_scripts"], **entry["host_scripts"]}
                network_config[ipv4_key] = entry
            else:
                existing["host_scripts"].update(entry["host_scripts"])

    return network_config


# ---------------------------------------------------------------------------
# Unchanged helper (kept for compatibility)
# ---------------------------------------------------------------------------

def all_xml_output_to_txt(target_file: str) -> str:
    """
    Concatenate all .xml files in *target_file* folder into a single .txt.
    Returns the output file path.
    """
    xml_folder = target_file
    xml_list = sorted(f for f in os.listdir(xml_folder) if f.endswith(".xml"))
    content = ""

    for xml in xml_list:
        xml_path = os.path.join(xml_folder, xml)
        if os.path.isfile(xml_path):
            with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
                content += f.read()
                content += "\n < --- END OF XML CONTENT --- > \n"
            print(f"Retrieved: {xml}")

    output_path = os.path.join(xml_folder, "xml_content.txt")
    with open(output_path, "w", encoding="utf-8") as c:
        c.write(content)
    print(f"Written to: {output_path}")

    return output_path