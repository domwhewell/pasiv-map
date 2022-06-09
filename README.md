# pasiv-map
A Passive Recon Network Map Tool

# Usage
To use the tool either a .pcapng file must be specified or an output must be specified to save the data to.
Use --file or --output for either of these options

The default output with no additional options will just show data it is able to gather from hosts. NAME (Via DNS queries from other hosts, NBT Lookups from other hosts), IPv4, IPv6, MAC, VLAN (From Tagged packets)
```bash
$ pasiv-map.py --file test.pcapng

HOSTNAME 192.168.0.1 ::ffff:c0a8:0001 (AB-CD-EF-12-34-56) [VLAN ID: 20]

HOSTNAME1 192.168.0.2 ::ffff:c0a8:0002 (AB-CD-EF-34-56-78) [VLAN ID: 20]
```

By using the --ports option ports will be added below each host
```bash
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
53/udp  Destination DNS     01/01/1999, 00:00:00
```
This shows that a packet was sent to port 53/udp on the host at Midnight Jan 1st 1999

It is common for devices to open high Source ports on devices to communicate with a service and then they will be closed for example;
```bash
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
55110/udp  Source MDNS     01/01/1999, 00:00:00
```
The above output is a high port that was opened temporarily you can filter only source and destination ports less than 1024 by using;
--port-filter 1024
This option will not show any ports over 1024 (Source or Destination)

The option --llmnr allows you to display LLMNR traffic that has been broadcast under each host;
```bash
The host broadcast LLMNR queries for;
HOSTNAME.
```

The option --search allows you to use a regex string to search in the RAW packet data;
--search 'xml version="1.0"'
This will print interesting packets below the network map
```bash
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

# Example Output

```bash
$ pasiv-map.py --file test.pcapng --ports --llmnr --search 'xml version="1.0"'

HOSTNAME 192.168.0.1 ::ffff:c0a8:0001 (AB-CD-EF-12-34-56) [VLAN ID: 20]
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
53/udp  Destination DNS     01/01/1999, 00:00:00

HOSTNAME1 192.168.0.2 ::ffff:c0a8:0002 (AB-CD-EF-34-56-78) [VLAN ID: 20]
PORT    DIRECTION   SERVICE FIRST TIMESTAMP
53/udp  Source DNS     01/01/1999, 00:00:00

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