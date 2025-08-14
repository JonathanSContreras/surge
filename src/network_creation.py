"""
@author: Brianna Hinds
Description: Parses an nmap .xml output and turns it into a networkx graph.
"""


import xml.etree.ElementTree as ET  # ElementTree library is used to parse XML data
import networkx as nx
import matplotlib.pyplot as plt

## XML PARSING ##
def xml_parse(xml_file):
    """
    Reads a .xml file and parses it storing network information. Returns a dictionary of important network components.

    ARGS
        xml_file: nmap scan .xml output
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()  # tag that envelopes everything (SAM)

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
            # ERROR PORTION (not getting all information)
            port_root = child.find("ports")
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
def dictionary_to_networkx(network_dict):
    """
    Takes a dictionary and visualizes the network defined.

    ARGS
        network_dict: Dictionary object containing network information.
    """
    G = nx.Graph()
    SCANNER = "SAM"
    # parse the dictionary to get the nodes (scanner -> IP -> Ports)
    G.add_node(SCANNER)

    for ip in network_dict.keys():
        G.add_node(ip, color="#4c956c" if network_dict[ip]["state"] == "up" else "#d9d9d9")  # adding a node to IP

        # if down connect using dashed lines
        if network_dict[ip]["state"] != "up":
            G.add_edge(SCANNER, ip)
        else:
            G.add_edge(SCANNER, ip)

        # add port edges
        if network_dict[ip]["ports"] is not None:
            for n in network_dict[ip]["ports"]:
                # color code port edges
                if n["portid"] in [80, 443]:
                    color = "#fb8500"
                elif n["portid"] == 22:
                    color = "#d9d9d9"
                else:
                    color = "#0077b6"

                service_label = f"{n['portid']}/{n.get('name', 'unknown')}"
                G.add_node(service_label)
                G.add_edge(ip, service_label, color=color)


    # display graph
    # pull the colors used
    node_colors = [G.nodes[n].get("color", "#0077b6") for n in G.nodes()]
    edge_colors = nx.get_edge_attributes(G, "color").values()
    node_degree = G.degree
    nx.draw(
        G,
        pos=nx.spring_layout(G),  # mess around with layouts
        # pos=nx.multipartite_layout(G, subset_key=""), 
        node_color=node_colors,
        edge_color=edge_colors,
        with_labels= True,
        node_size=[v[1] * 200 for v in node_degree]
    )

    # save the fig as the name of the nmap command
    plt.savefig("nmap_out_ad.png")
    plt.show()

def main():
    # run both xml parser and network creator
    xml1 = "../data/nmap_output.xml"
    xml2 = "../data/nmap_output_adv.xml"
    xml3 = "../data/nmap_stress_test.xml"

    network = xml_parse(xml1)
    dictionary_to_networkx(network)

if __name__ == "__main__":
    main()