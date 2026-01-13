"""
The idea of this code is an IP address of the device can be acquired based on the scan.
This becomes helpful when we switch from hardcoding the IP address to scanning for our "entry point".
"""

import socket
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # create an ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # layer broadcasts the ARP request
    arp_request_broadcast = broadcast / arp_request   # combine the Ether and ARP layers
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # send the packet and receive the response
    
    clients_list = []
    for element in answered_list:
        clients_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients_list

def display_result(results):
    print("IP Address\t\tMAC Address\n")
    for client in results:
        print(client["ip"] + "\t\t" + client["mac"])

# get my IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
sockname = s.getsockname()[0]
print(sockname)
s.close()

ip_address = str.split(sockname, sep=".")
print(ip_address)

# ip_address[2] = "1"
ip_address[3] = "0/16"

print(ip_address)

updated_ip = ".".join(ip_address)

print(updated_ip)

display_result(scan(updated_ip))