'''
 -*- coding: utf-8 -*-
 @Time    : 2021/11/18 20:50
 @Author  : Yun981128
 @Email   : yun981128@gmail.com
 @File    : pars_pcap_by_scapy.py
 @Software: PyCharm
'''
from scapy.all import rdpcap

packets=rdpcap("file/幻塔.pcapng")

for session in packets.sessions():
    print(session)
    print(len(session))
    for packet in packets.sessions()[session]:
        pass
        # print(repr(packet))
    print("="*50)


def load_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    return packets






