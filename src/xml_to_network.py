"""
@author: Brianna Hinds
Description: Parses an nmap .xml output and turns it into a networkx graph.
"""

import os
import xml.etree.ElementTree as ET  # ElementTree library is used to parse XML data
import networkx as nx
import matplotlib.pyplot as plt

## XML PARSING ##
def xml_parse(xml_input):
    """
    Reads a .xml file and parses it storing network information. 
    Returns the nmap command used and a dictionary of important network components.

    ARGS
        xml_file: nmap scan .xml output
    """
    if not xml_input:
        return {}
    
    # get the xml_ouput (either string or XML file)
    try:
        if os.path.exists(xml_input):
            tree = ET.parse(xml_input)
            root = tree.getroot()
        else:
            s = xml_input.strip()

            if not (s.startswith("<")):  # check if the string is XML looking
                return {"error": "~INPUT DOES NOT APPEAR TO BE XML"}
            
            root = ET.fromstring(s)

    except ET.ParseError as pe:
        return {"error": f"~ISSUE PARSING ELEMENTTREE: {pe}"}
    except Exception as e:
        return {"error": f"~UNEXPECTED ERROR PARSING XML: {e}"}

    # loop over root children and their sub attributes
    # network info will be housed in a dictionary
    network = {}
    for child in root: 
        network_config = {}

        # skip over none host elements
        if child.tag != "host":
            continue

        # pull all IP hosts found (up/down)
        addr = child.findall("address")  # might not be universal (can have ipv4/mac)
        ip_addr = None
        mac_addr = None
        for a in addr:
            # store ipv4 as the main key
            if a.attrib["addrtype"] == "ipv4":
                ip_addr = a.attrib["addr"]

            # if a mac address exists store it
            if a.attrib["addrtype"] == "mac":
                # store other address types
                mac_addr = a.attrib["addr"]
                vendor = a.attrib.get("vendor", None)
                network_config["address"] = {"mac_addr" : mac_addr, "vendor": vendor}

        # use mac as main key if ipv4 not available
        if not ip_addr and mac_addr is not None:
            print("~NO IPV4 VALUE USING MAC INSTEAD")
            ip_addr = mac_addr
            
        # find host's state
        status = child.find("status").attrib["state"]
        if status != "up":  # host is down
            network_config["os"] = None
            network_config["state"] = None
            network_config["hostname"] = None
            network_config["ports"] = None
        else:   # host is up
            # find IP hostname (might contain multiple or none)
            hostname_root = child.find("hostnames")
            if hostname_root is not None:
                hostname_list = []
                for host in hostname_root:
                    hostname_list.append(host.attrib) 
            else:
                hostname_list = None

            # find IP OS (either single or multiple)
            os_root = child.find("os")
            if os_root is not None:
                osmatch = os_root.findall("osmatch")
                os_lst = []
                for o in osmatch:
                    os_pred = o.attrib
                    os_lst.append(os_pred)
                network_config["os"] = os_lst
            else: 
                network_config["os"] = None

            network_config["state"] = status 
            network_config["hostname"] = hostname_list  # store list of hostnames if contains multiple

            # find IP open ports
            port_root = child.find("ports")
            print(port_root)
            if port_root is not None:
                port_lst = []
                for port in port_root.findall("port"):
                    port_data = dict(port.attrib)
                    for child in port:
                        if child.tag in ("state", "service"):
                            port_data.update(child.attrib)
                    port_lst.append(port_data)

                network_config["ports"] = port_lst

        # add the host into the dictionary
        network[ip_addr] = network_config

    return network

## NETWORK CREATION ##
def dictionary_to_networkx(network_dict, cmd="COMMAND"):
    """
    Takes a dictionary and visualizes the network defined.

    ARGS
        network_dict: Dictionary object containing network information.
        cmd: nmap command
    """
    G = nx.Graph()
    SCANNER = "SAM"
    PORT_COLORS = {
        80: "#fb8500",  # web
        443: "#fb8500",  # web
        22: "#d9d9d9"  # ssh
    }

    # parse the dictionary to get the nodes (scanner -> IP -> Ports)
    G.add_node(SCANNER, color="#8ecae6")

    # # connect to first host
    # first_ip = next(iter(network_dict.keys()))
    # G.add_edge(SCANNER, first_ip, style="dashed")

    for ip in network_dict.keys():
        state = network_dict[ip].get("state", "unknown")
        G.add_node(ip, color="#4c956c" if state == "up" else "#d9d9d9")  # adding a node to IP
        G.add_edge(SCANNER, ip)
        # # if down connect using dashed lines
        # if state != "up":
        #     G.add_edge(SCANNER, ip)
        # else:
        #     G.add_edge(SCANNER, ip)

        # add port edges
        p = network_dict[ip].get("ports", [])
        # if network_dict[ip]["ports"] is not None:
        if p:
            for n in network_dict[ip]["ports"]:
                # color code port edges
                # color = PORT_COLORS.get(int(n["portid"]), "#0077b6")
                service_label = f"{n['portid']}/{n.get('name', 'unknown')}"

                G.add_node(service_label)
                G.add_edge(ip, service_label, color="#0077b6")

    # display graph
    # pull the colors used
    node_colors = [G.nodes[n].get("color", "#0077b6") for n in G.nodes()]
    edge_colors = nx.get_edge_attributes(G, "color").values()
    cleaned_edge = edge_colors if edge_colors else "black"     
    node_degree = G.degree
    nx.draw(
        G,
        pos=nx.spring_layout(G),  # mess around with layouts
        # pos=nx.shell_layout(G),
        # pos=nx.multipartite_layout(G, subset_key=""), 
        node_color=node_colors,
        edge_color=cleaned_edge,
        with_labels=True,
        node_size=[v[1] * 200 for v in node_degree]
    )

    # save the fig as the name of the nmap command
    plt.savefig(f"{cmd}.png")
    plt.show()

def main():
    # run both xml parser and network creator
    xml1 = "./data/nmap_output.xml"
    xml2 = "./data/nmap_output_adv.xml"
    xml3 = "./data/nmap_stress_test.xml"
    xml4 = "./192_168_1_0_24/2026-02-08T17_52_59_681322Z_nmap.xml"

    network = xml_parse(xml4)
    print(network)
    dictionary_to_networkx(network, cmd="full_test_run_home")

def main_string():
    # minimal nmap XML string
    xml_str = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -oX - localhost" start="1695580000" version="7.94" xmloutputversion="1.05">
      <host>
        <status state="up" reason="syn-ack" reason_ttl="64"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="localhost" type="user"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="ssh" method="table" conf="3"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="closed" reason="reset" reason_ttl="64"/>
            <service name="http" method="table" conf="3"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 5.X" accuracy="98"/>
        </os>
      </host>
    </nmaprun>
    """

    # call your parser with a string
    network = xml_parse(xml_str)

    print("Parsed dictionary:\n", network)
    dictionary_to_networkx(network)


if __name__ == "__main__":
    main()
    # main_string()