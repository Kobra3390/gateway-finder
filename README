# Gateway Finder

> Python3 implementation of the original project by [pentestmonkey](https://github.com/pentestmonkey).

The homepage for this project is:
http://pentestmonkey.net/tools/gateway-finder

Gateway-finder is a Python script based on Scapy that helps you identify which systems on the local LAN have IP forwarding enabled and can reach the Internet. This tool is particularly useful during internal penetration tests to quickly identify unauthorized routes to the Internet (e.g., rogue wireless access points) or routes to other internal LANs. While not exhaustive, it provides quick and actionable insights. Being written in Python, it is also easy to modify to suit your specific needs.

## Overview

The script probes the local LAN to identify potential gateways to the Internet by sending the following types of packets:

* Standard ICMP Ping
* TCP SYN packet to port 80
* ICMP Ping with TTL set to 1
* TCP SYN packet to port 80 with TTL set to 1

It reports which systems respond with an ICMP "TTL exceeded in transit" message (indicating they are routers) and which respond to the probe (indicating they are gateways to the Internet).

## Dependencies

Gateway-finder requires Python and Scapy. To install Scapy on Debian/Ubuntu, use:

```shell
sudo apt-get install python3-scapy
```

For other operating systems, follow the specific instructions to install Scapy.

## Usage

To see all available options, run:

```shell
python3 gateway-finder.py -h
```

Example usage:

```shell
Usage: gateway-finder.py [ -I interface ] -i ip -f macs.txt
```

This command attempts to find a layer-3 gateway to the Internet by sending ICMP ping and TCP SYN packets to port 80 via each potential gateway listed in `macs.txt`.

## Steps

### Step 1: Run an ARP scan to identify systems on the local LAN

Use your preferred ARP scanning tool to identify systems on the local LAN. Save the output for use in the next step. For example, using `arp-scan`:

```shell
arp-scan -l | tee arp.txt
```

Sample output:

```shell
Interface: eth0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.6 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
10.0.0.100     00:13:72:09:ad:76       Dell Inc.
10.0.0.200     00:90:27:43:c0:57       INTEL CORPORATION
10.0.0.254     00:08:74:c0:40:ce       Dell Computer Corp.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.6: 256 hosts scanned in 2.099 seconds (121.96 hosts/sec).  3 responded
```

### Step 2: Run gateway-finder on the list of local systems

Gateway-finder requires two inputs from you:

* The MAC addresses of potential gateways
* The IP address of a system on the Internet (e.g., a Google IP address)

If your `arp.txt` also contains the IP address of each system on the same line as the MAC, the output will be more informative. If you need to use a different network interface, use the `-I` option.

Example command:

```shell
python3 gateway-finder.py -f arp.txt -i 209.85.227.99
```

Sample output:

```shell
gateway-finder v1.1 http://pentestmonkey.net/tools/gateway-finder

[+] Using interface eth0 (-I to change)
[+] Found 3 MAC addresses in arp.txt
[+] 00:13:72:09:AD:76 [10.0.0.100] appears to route ICMP Ping packets to 209.85.227.99. Received ICMP TTL Exceeded in transit response.
[+] 00:13:72:09:AD:76 [10.0.0.100] appears to route TCP packets 209.85.227.99:80. Received ICMP TTL Exceeded in transit response.
[+] We can ping 209.85.227.99 via 00:13:72:09:AD:76 [10.0.0.100]
[+] We can reach TCP port 80 on 209.85.227.99 via 00:13:72:09:AD:76 [10.0.0.100]
[+] Done
```
