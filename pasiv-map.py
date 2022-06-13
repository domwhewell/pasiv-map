#!/usr/bin/python3
import argparse, socket, re, base64
from datetime import datetime
from collections import Counter
from scapy.all import rdpcap, sniff, wrpcap
from argparse import RawTextHelpFormatter

lgreen = "\033[1;32;49m"
lred = "\033[1;31;49m"
yellow = "\033[1;33;49m"
white = "\033[1;37;49m"

welcome_msg = '''A tool to analyze .pcap files and print a readable network map output.
By Default the tool will print only visible hosts from the .pcap file; Obtaining the Hostname from any DNS responses or NBTName's seen in the packets
HOSTNAME 192.168.0.1 ::ffff:c0a8:0001 (AB-CD-EF-12-34-56) [VLAN ID: 20]

HOSTNAME1 192.168.0.2 ::ffff:c0a8:0002 (AB-CD-EF-34-56-78) [VLAN ID: 20]

If using the --ports option ports will be added below each host;
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
53/udp  Destination DNS     01/01/1999, 00:00:00

The above port output is showing that a packet was sent to port 53/udp on the host at Midnight Jan 1st 1999

It is common for devices to open high Source ports on devices to communicate with a service and then they will be closed for example;
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
55110/udp  Source MDNS     01/01/1999, 00:00:00

The above output is a high port that was opened temporarily you can filter only source and destination ports less than 1024 by using;
--port-filter 1024
This option will not show any ports over 1024 (Source or Destination)

You can only display destination ports by using the option --only-destination

The option --llmnr allows you to display LLMNR traffic that has been broadcast under each host;
The host broadcast LLMNR queries for;
HOSTNAME.

The option --search allows you to use a regex string to search in the RAW packet data;
--search 'xml version="1.0"'
This will print interesting packets below the network map
```
[+] Interesting Packets found based on your search regex;
###[ Ethernet ]###
  dst       = AB-CD-EF-12-34-56
  src       = AB-CD-EF-34-56-78
  type      = IPv6
###[ IPv6 ]###
     version   = 6
     tc        = 0
     fl        = 729563
     plen      = 664
     nh        = UDP
     hlim      = 1
     src       = ::ffff:c0a8:0001
     dst       = ::ffff:c0a8:0002
###[ UDP ]###
        sport     = 64753
        dport     = 3702
        len       = 664
        chksum    = 0x1acb
###[ Raw ]###
           load      = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:6a36987e-8408-4977-b74d-60e1bccbce4d</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:c5c8cfab-14f2-566d-8bfe-d8764cbafe81</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>'
```

Note: The Hostnames, IPv4, IPv6, VLAN ID, Services, Broadcasts and RAW packet data are all subject to showing more/less data dependent on the contents of the passive recon. At the very least MAC address's of discovered devices will be shown.
'''

parser = argparse.ArgumentParser(description=welcome_msg.strip(), formatter_class=RawTextHelpFormatter)
run = parser.add_mutually_exclusive_group(required=True)
run.add_argument("-f", "--file", help="Set the pcap file")
run.add_argument("-o", "--output", help="If file is not used use this argument to capture network traffic and save to .pgcapng file.")
parser.add_argument("-p", "--ports", action="store_true", help="Include source and destination ports, source ports can clutter up the output so a filter or only showing the destination is reccomended.")
parser.add_argument("-pf", "--port-filter", help="Use this to filter the visible ports, Sometimes windows systems make alot of noise on ports > 10000 you can use this option to only show ports Less than X. e.g. pasiv-map.py -f input.pcap --ports --port-filter 10000 - this will show ports less than 10000")
parser.add_argument("-d", "--only-destination", action="store_true", help="Only Display Destination Ports.")
parser.add_argument("--llmnr", action="store_true", help="Include LLMNR broadcast traffic seen underneath each host.")
parser.add_argument("--syslog", action="store_true", help="Include Syslog traffic seen underneath each host.")
parser.add_argument("--credentials", action="store_true", help="Print any discovered credentials. HTTP Basic / Digest")
parser.add_argument("-s", "--search", help="Use a regex to search in the raw data in the packets")
args = parser.parse_args()

def pprint(network):
    for mac in network:
        if mac != "ff:ff:ff:ff:ff:ff":
            host = []
            if "NBTName" in network[mac]:
                host.append(network[mac]['NBTName'])
            elif "DNS" in network[mac]:
                host.append(network[mac]['DNS'])
            if "ipv4" in network[mac]:
                host.append(network[mac]['ipv4'])
            if "ipv6" in network[mac]:
                host.append(network[mac]['ipv6'])
            host.append("("+mac+")")
            if "vlan_id" in network[mac]:
                host.append("[VLAN ID: "+str(network[mac]['vlan_id'])+"]")
            print(" ".join(host))
            if args.ports:
                if "ports" in network[mac]:
                    print ("{:<8} {:<15} {:<10} {:<10}".format('PORT','DIRECTION','SERVICE','FIRST TIMESTAMP'))
                    for port, protocol, direction, timestamp  in sorted(network[mac]['ports']):
                        try:
                            service = socket.getservbyport(port, protocol)
                        except OSError:
                            service = ""
                        if args.port_filter:
                            if port > int(args.port_filter):
                                continue
                        if args.only_destination:
                            if direction != "Destination":
                                continue
                        print ("{:<8} {:<15} {:<10} {:<10}".format(str(port)+"/"+protocol, direction, service, datetime.fromtimestamp(timestamp).strftime("%d/%m/%Y, %H:%M:%S")))
            if args.llmnr:
                if "LLMNR_queries" in network[mac]:
                    print("The host broadcast LLMNR queries for;")
                    for llmnr_query in network[mac]['LLMNR_queries']:
                        print(llmnr_query)
            if args.syslog:
                if "SYSLOG_data" in network[mac]:
                    print("The following syslog traffic was found;")
                    for syslog_data in network[mac]['SYSLOG_data']:
                        print(syslog_data)
        print()

def sniff_to_file(output):
    print(lgreen+"[+]"+white+" Listening for packets on the network, once you press CTRL+C output will be saved to "+output+" and will auto run an analysis using the options specified.")
    packets = sniff()
    wrpcap(output, packets)

def process_http(data):
    response = ""
    for line in data.splitlines():
        coded_string = ""
        if "Authorization:" in line:
            if "Basic" in line:
                coded_string = line.split('Basic')[1].strip()
                response = "(HTTP Basic Authentication) "+base64.b64decode(coded_string).decode()
            elif "Digest" in line:
                response = "(HTTP Digest Authentication) "+line.split('response="')[1].split('"')[0]
    return response

def analyse_packet(packet):
    # Get all the information we can from the source Key will be the MAC address
    if packet.src not in network_map:
        network_map.update({packet.src:{}})
    if packet.dst not in network_map:
        network_map.update({packet.dst:{}})
    for payload in packet.iterpayloads():
        if payload.__class__.__name__ == "IP":
            if hasattr(payload, "src"):
                network_map[packet.src]['ipv4'] = payload.src
            if hasattr(payload, "dst"):
                network_map[packet.dst]['ipv4'] = payload.dst
        elif payload.__class__.__name__ == "IPv6":
            if hasattr(payload, "src"):
                network_map[packet.src]['ipv6'] = payload.src
            if hasattr(payload, "dst"):
                network_map[packet.dst]['ipv6'] = payload.dst
        elif payload.__class__.__name__ == "Dot1Q":
            if hasattr(payload, "vlan"):
                network_map[packet.src]['vlan_id'] = payload.vlan
                network_map[packet.dst]['vlan_id'] = payload.vlan
        elif payload.__class__.__name__ == "TCP" or payload.__class__.__name__ == "UDP":
            if hasattr(payload, "sport"):
                 if "ports" in network_map[packet.src]:
                     if (payload.sport, payload.__class__.__name__.lower(), "Source") not in [(i[0], i[1], i[2]) for i in network_map[packet.src]['ports']]:
                         network_map[packet.src]['ports'].append((payload.sport, payload.__class__.__name__.lower(), "Source", int(packet.time)))
                 else:
                     network_map[packet.src]['ports'] = [(payload.sport, payload.__class__.__name__.lower(), "Source", int(packet.time))]
            if hasattr(payload, "dport"):
                 if "ports" in network_map[packet.dst]:
                     if (payload.dport, payload.__class__.__name__.lower(), "Destination") not in [(i[0], i[1], i[2]) for i in network_map[packet.src]['ports']]:
                         network_map[packet.dst]['ports'].append((payload.dport, payload.__class__.__name__.lower(), "Destination", int(packet.time)))
                 else:
                     network_map[packet.dst]['ports'] = [(payload.dport, payload.__class__.__name__.lower(), "Destination", int(packet.time))]
        elif payload.__class__.__name__ == "NBTDatagram":
            if hasattr(payload, "SourceName"):
                network_map[packet.src]['NBTName'] = payload.SourceName.decode("utf-8").strip()
            if hasattr(payload, "DestinationName"):
                network_map[packet.dst]['NBTName'] = payload.DestinationName.decode("utf-8").strip()
        elif payload.__class__.__name__ == "LLMNRQuery":
            if "LLMNR_queries" in network_map[packet.src]:
                if payload.qd.qname.decode("utf-8").strip() not in network_map[packet.src]['LLMNR_queries']:
                    network_map[packet.src]['LLMNR_queries'].append(payload.qd.qname.decode("utf-8").strip())
            else:
                network_map[packet.src]['LLMNR_queries'] = [payload.qd.qname.decode("utf-8").strip()]
        elif payload.__class__.__name__ == "DNSRR":
            if hasattr(payload, "rrname") and hasattr(payload, "type") and hasattr(payload, "rdata"):
                if payload.type == 1:
                    # Insert the DNS name against the IP
                    for mac in network_map:
                        if hasattr(network_map[mac], "ipv4"):
                            if network_map[mac]['ipv4'] == payload.rdata:
                                network_map[mac]['DNS'] = payload.rrname.decode("utf-8").strip()
                if payload.type == 28:
                    # Insert the DNS name against the IP
                    for mac in network_map:
                        if hasattr(network_map[mac], "ipv6"):
                            if network_map[mac]['ipv6'] == payload.rdata:
                                network_map[mac]['DNS'] = payload.rrname.decode("utf-8").strip()
        elif payload.__class__.__name__ == "Raw":
            try:
                raw_data = payload.load.decode().strip()
            except:
                # If we cant decode skip to the next packet
                continue
            if args.search:
                if re.search(args.search, raw_data):
                    interesting_packets.append(packet)
            if args.syslog:
                if payload.underlayer.dport == 514:
                    if "SYSLOG_data" in network_map[packet.src]:
                        if raw_data not in network_map[packet.src]['SYSLOG_data']:
                            network_map[packet.src]['SYSLOG_data'].append(raw_data)
                    else:
                        network_map[packet.src]['SYSLOG_data'] = [raw_data]
            if args.credentials:
                if "HTTP/1.1" in raw_data:
                    authorization = process_http(raw_data)
                    if authorization:
                        if network_map[packet.src].get('ipv4') and network_map[packet.dst].get('ipv4'):
                            line = network_map[packet.src]['ipv4']+"=>"+network_map[packet.dst]['ipv4']+" => "+authorization
                        elif network_map[packet.src].get('ipv6') and network_map[packet.dst].get('ipv6'):
                            line = network_map[packet.src]['ipv6']+"=>"+network_map[packet.dst]['ipv6']+" => "+authorization
                        if line not in credential_packets:
                            credential_packets.append(line)

if __name__ == "__main__":
    network_map = {}
    interesting_packets = []
    credential_packets = []
    if args.file:
        print(lgreen+"[+]"+white+" Loading from pcap file: "+args.file)
        sniff(offline=args.file, prn=analyse_packet, store=0)
    elif args.output:
        sniff_to_file(args.output)
        print(lgreen+"[+]"+white+" Loading from pcap file: "+args.output)
        sniff(offline=args.output, prn=analyse_packet, store=0)
    else:
        print(lred+"[!]"+white+" Error --file or --output must be specified.")
        exit()
    pprint(dict(sorted(network_map.items(), key=lambda x: x[1].get('vlan_id', 0))))
    if interesting_packets:
        print(lgreen+"[+]"+white+" Interesting Packets found based on your search regex;")
        for packet in interesting_packets:
            print(packet.show())
    if credential_packets:
        print(lgreen+"[+]"+white+" Packets Containing Credentials found;")
        for line in credential_packets:
            print(line)
