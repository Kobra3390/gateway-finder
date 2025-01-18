#!/usr/bin/env python3
# gateway-finder - Tool to identify routers on the local LAN and paths to the Internet
# Copyright (C) 2011 pentestmonkey@pentestmonkey.net
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as 
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  If these terms are not acceptable to 
# you, then do not use this tool.
# 
# You are encouraged to send comments, improvements or suggestions to
# me at pentestmonkey at pentestmonkey.net
#

import logging
import sys
import os
import re
import signal
from time import sleep
from tkinter import TOP
from scapy.all import *
from optparse import OptionParser

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

parser = OptionParser(usage="Usage: %prog [ -I interface ] -i ip -f macs.txt\n\nTries to find a layer-3 gateway to the Internet. Attempts to reach an IP\naddress using ICMP ping and TCP SYN to port 80 via each potential gateway\nin macs.txt (ARP scan to find MACs)")
parser.add_option("-i", "--ip", dest="ip", help="Internet IP to probe")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
parser.add_option("-I", "--interface", dest="interface", default="eth0", help="Network interface to use")
parser.add_option("-f", "--macfile", dest="macfile", help="File containing MAC addresses")

(options, args) = parser.parse_args()

if not options.macfile:
    print("[E] No macs.txt specified.  -h for help.")
    sys.exit(0)

if not options.ip:
    print("[E] No target IP specified.  -h for help.")
    sys.exit(0)

version = "1.1"
print(f"gateway-finder v{version} http://pentestmonkey.net/tools/gateway-finder\n")
print(f"[+] Using interface {options.interface} (-I to change)")

with open(options.macfile, 'r') as macfh:
    lines = [line.strip() for line in macfh.readlines()]

macs = []
ipofmac = {}
for line in lines:
    mac_match = re.search(r'([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})', line)
    if mac_match:
        mac = mac_match.group(1).upper()
        ipofmac[mac] = "UnknownIP"
        ip_match = re.search(r'(\d{1,3}(\.\d{1,3}){3}).*?([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})', line)
        if ip_match:
            ipofmac[mac] = ip_match.group(1)

macs = list(ipofmac.keys())
print(f"[+] Found {len(macs)} MAC addresses in {options.macfile}")

if len(macs) == 0:
    print(f"[E] No MAC addresses found in {options.macfile}")
    sys.exit(0)

def handler(signum, frame):
    vprint(f"Child process received signal {signum}. Exiting.")
    sys.exit(0)

def vprint(message):
    if options.verbose:
        print(f"[-] {message}")

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

def processreply(p):
    try:
        if p.haslayer(IP): # type: ignore
            if p[IP].proto == 1:  # type: ignore # ICMP
                if p.haslayer(ICMP) and p[ICMP].type == 11 and p[ICMP].code == 0: # type: ignore
                    if p.haslayer(ICMPerror): # type: ignore
                        seq = p[ICMPerror].seq # type: ignore
                        vprint(f"Received reply: {p.summary()}")
                        print(f"[+] {packets[seq]['message']}")
                elif p.haslayer(ICMP): # type: ignore
                    seq = p[ICMP].seq # type: ignore
                    vprint(f"Received reply: {p.summary()}")
                    print(f"[+] {packets[seq]['message']}")
            elif p[IP].proto == 6:  # type: ignore # TCP
                if p[IP].src == options.ip and p.haslayer(TCP) and p[TCP].sport == 80: # type: ignore
                    seq = p[TOP].ack - 1
                    vprint(f"Received reply: {p.summary()}")
                    print(f"[+] {packets[seq]['message']}")
    except Exception as e:
        print(f"[E] Received unexpected packet. Ignoring. Error: {e}")
    return None 

seq = 0
packets = {}
for mac in macs:
    packets[seq] = {
        'packet': Ether(dst=mac)/IP(dst=options.ip, ttl=1)/ICMP(seq=seq), # type: ignore
        'message': f'{mac} [{ipofmac[mac]}] appears to route ICMP Ping packets to {options.ip}. Received ICMP TTL Exceeded in transit response.'
    }
    seq += 1

    packets[seq] = {
        'packet': Ether(dst=mac)/IP(dst=options.ip, ttl=1)/TCP(seq=seq), # type: ignore
        'message': f'{mac} [{ipofmac[mac]}] appears to route TCP packets {options.ip}:80. Received ICMP TTL Exceeded in transit response.'
    }
    seq += 1

    packets[seq] = {
        'packet': Ether(dst=mac)/IP(dst=options.ip)/ICMP(seq=seq), # type: ignore
        'message': f'We can ping {options.ip} via {mac} [{ipofmac[mac]}]'
    }
    seq += 1

    packets[seq] = {
        'packet': Ether(dst=mac)/IP(dst=options.ip)/TCP(seq=seq), # type: ignore
        'message': f'We can reach TCP port 80 on {options.ip} via {mac} [{ipofmac[mac]}]'
    }
    seq += 1

pid = os.fork()
if pid:
    sleep(2)
    vprint("Parent process sending packets...")
    for packet in packets.values():
        sendp(packet['packet'], verbose=0)
    vprint("Parent finished sending packets")
    sleep(2)
    vprint("Parent killing sniffer process")
    os.kill(pid, signal.SIGTERM)
    vprint("Parent reaping sniffer process")
    os.wait()
    vprint("Parent exiting")
    print("[+] Done\n")
    sys.exit(0)
else:
    filter_str = f"ip and not arp and ((icmp and icmp[0] = 11 and icmp[1] = 0) or (src host {options.ip} and (icmp or (tcp and port 80))))"
    vprint(f"Child process sniffing on {options.interface} with filter '{filter_str}'")
    sniff(iface=options.interface, store=0, filter=filter_str, prn=processreply)
