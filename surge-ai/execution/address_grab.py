"""
@author: Brianna Hinds
Description: Figures out where we are on the network and builds the initial target list for the recon agent without hardcoding.
"""

from config.logging_config import get_logger

import re
import socket
import scapy.all as scapy
import platform
import subprocess

# define global log file
logger = get_logger(__name__)

# IPv4 validation pattern
IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


## --- IP FIND HELPER FUNCTIONS --- ##
def _get_local_ip():
    """
    After WiFi connection, gets device's IP by routing towards a public address.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def _arp_scan(ip:str) -> list[dict]:
    arp_request = scapy.ARP(pdst=ip)  # create an ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # layer broadcasts the ARP request
    arp_request_broadcast = broadcast / arp_request   # combine the Ether and ARP layers
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]  # send the packet and receive the response

    return [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

def _get_gateway_ip() -> str | None:
    """
    Parse the default gateway from the OS routing table.

    Windows  → route print 0.0.0.0
    Linux    → ip route show default
    macOS    → netstat -rn

    The gateway is the router sitting between your subnet and everything
    else — knowing it tells us the network boundary we're behind and
    whether the gateway lives on a different /24 (common in enterprise
    environments with separate management VLANs).

    Returns None if detection fails — calling code handles this gracefully.
    """
    system = platform.system()
    logger.info(f"Detecting gateway on platform: {system}")

    try:
        if system == "Windows":
            # Output format:
            # Network    Netmask      Gateway        Interface     Metric
            # 0.0.0.0    0.0.0.0      10.10.160.1    10.10.160.96  25
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("0.0.0.0"):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        if IPV4_PATTERN.match(gateway):
                            logger.info(f"Gateway detected (Windows): {gateway}")
                            return gateway

        elif system == "Linux":
            # Output format:
            # default via 10.10.160.1 dev eth0 proto dhcp
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                gateway = match.group(1)
                logger.info(f"Gateway detected (Linux): {gateway}")
                return gateway

        elif system == "Darwin":
            # Output format:
            # default    10.10.160.1    UGScg   en0
            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith("default"):
                    parts = line.split()
                    if len(parts) >= 2 and IPV4_PATTERN.match(parts[1]):
                        gateway = parts[1]
                        logger.info(f"Gateway detected (macOS): {gateway}")
                        return gateway

        else:
            logger.warning(f"Unsupported platform for gateway detection: {system}")

    except Exception as e:
        logger.warning(f"Could not determine gateway on {system}: {e}")

    return None

def _derive_targets(local_ip: str, gateway_ip: str | None) -> list[str]:
    """
    Build the nmap target list from what we know about ourselves.

    Strategy (in order):
      1. Our own /24  — guaranteed reachable, ARP-seeded, always first
      2. Gateway /24  — added only if gateway lives on a different subnet
                        (indicates a management VLAN or split network)
      3. /22 supernet — covers 4 adjacent /24s so the recon agent LLM
                        can escalate into neighbouring subnets naturally

    The /22 base address is derived by zeroing the last 2 bits of the
    third octet (rounding down to the nearest multiple of 4):
        10.10.160.x  →  c_base = (160 // 4) * 4 = 160  →  10.10.160.0/22
        10.10.162.x  →  c_base = (162 // 4) * 4 = 160  →  10.10.160.0/22
        10.10.164.x  →  c_base = (164 // 4) * 4 = 164  →  10.10.164.0/22

    We never go broader than /22 here — /16 is 65k addresses and is
    too slow as a seed. The recon agent's LLM escalates beyond /22 if
    it discovers evidence of a larger network.
    """
    octets   = local_ip.split(".")
    a, b, c  = octets[0], octets[1], octets[2]

    # 1. Local /24
    local_24 = f"{a}.{b}.{c}.0/24"
    targets  = [local_24]

    # 2. Gateway /24 (if on a different subnet)
    if gateway_ip:
        gw_octets = gateway_ip.split(".")
        gw_24     = f"{gw_octets[0]}.{gw_octets[1]}.{gw_octets[2]}.0/24"
        if gw_24 != local_24:
            targets.append(gw_24)
            logger.info(f"Gateway on separate subnet — adding: {gw_24}")

    # 3. /22 supernet
    c_base = (int(c) // 4) * 4
    net_22 = f"{a}.{b}.{c_base}.0/22"
    if net_22 != local_24:
        targets.append(net_22)

    logger.info(f"Derived initial targets: {targets}")
    return targets


def build_initial_target_lists() -> dict:
    """
    Docstring for build_initial_target_lists
    
    :return: Description
    :rtype: dict
    """
    local_ip = _get_local_ip()
    gateway_ip = _get_gateway_ip()

    logger.info(f"Local IP: {local_ip}")
    logger.info(f"Gateway: {gateway_ip if gateway_ip else 'not detected'}")

    # ARP sweep local /24 — fast confirmation we're on the network
    octets   = local_ip.split(".")
    local_24 = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    try:
        arp_hits = _arp_scan(local_24)
        logger.info(
            f"ARP sweep of {local_24} found {len(arp_hits)} hosts: "
            f"{[h['ip'] for h in arp_hits]}"
        )
    except Exception as e:
        logger.warning(f"ARP sweep skipped (requires root on macOS): {e}")
        arp_hits = []

    targets = _derive_targets(local_ip, gateway_ip)

    return {
        "scan_type":  "low",
        "targets":    targets,
        "local_ip":   local_ip,
        "gateway_ip": gateway_ip,
    }


if __name__ == "__main__":
    state_seed = build_initial_target_lists()
    print(f"LOCAL IP: {state_seed['local_ip']}")
    print(f"TARGETS: {state_seed['targets']}")
    print(f"ARP SEEDS: {state_seed['recon_seen_hosts']}")