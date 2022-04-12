#!/bin/env python3
from scapy.all import *
from collections import Counter
from time import localtime, strftime
import threading
import logging


attack_flag = False
syn_count = Counter()
logging.basicConfig(filename='traffic_analysis.log', format='%(message)s', level=logging.INFO)


def flow(pkt):

    global attack_flag

    # Flow labels log
    if IP in pkt:
        # source IP
        ipsrc = str(pkt[IP].src)
        # destination IP
        ipdst = str(pkt[IP].dst)
        try:
            # source port
            sport = str(pkt[IP].sport)
            # destination port
            dport = str(pkt[IP].dport)               
        except:
            sport = ""
            dport = ""
        # protocol
        prtcl = pkt.getlayer(2).name                 

        flow = '{:<4} | {:<16} | {:<6} | {:<16} | {:<6} | '.format(prtcl, ipsrc, sport, ipdst, dport)
        print(flow)

    # TCP SYN packet
    if TCP in pkt and pkt[TCP].flags & 2:
        src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
        syn_count[src] += 1
        if syn_count.most_common(1)[0][1] > 25 and pkt.ack == 0:
            attack_flag = True

class ClearCacheThread(threading.Thread):

    def run(self):

        global attack_flag

        while True:
            cur_time = strftime("%a, %d %b %Y %X", localtime())
            if not attack_flag or not syn_count:
                logging.info(cur_time + " Everything is normal")
            else:
                logging.info(cur_time + " SYN attack detected! IP: " + str(syn_count.most_common(1)[0][0]) +
                             " No. of attempts: " + str(syn_count.most_common(1)[0][1]))
                attack_flag = False
            syn_count.clear()
            time.sleep(3.5)

ClearCacheThread().start()
sniff(prn=flow, store=0)
