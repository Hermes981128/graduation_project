'''
 -*- coding: utf-8 -*-
 @Time    : 2021/11/11 17:32
 @Author  : Yun981128
 @Email   : yun981128@gmail.com
 @File    : pars_pcap.py
 @Software: PyCharm
'''

try:
    import scapy.all as scapy
except ImportError:
    import scapy
import re


# from scapy.utils import PcapReader


class PcapInstance():
    def __init__(self, path: str):
        self.packets = scapy.rdpcap(path)
        self.packet_num = len(self.packets)
        self.index = 0

    def __getitem__(self, item):
        if self.index >= self.packet_num:
            raise StopIteration('停止遍历')  # 抛出异常
        self.index = self.index + 1
        return PacketInstance(self.packets[self.index])


class PacketInstance():
    def __init__(self, packet):
        self.version = packet.version
        self.ihl = packet.ihl
        self.tos = packet.tos
        self.len = packet.len
        self.id = packet.id
        self.ip_flags = packet.flags
        self.frag = packet.frag
        self.ttl = packet.ttl
        self.proto = packet.proto
        self.chksum = packet.chksum
        self.src = packet.src
        self.dst = packet.dst
        self.sport = packet.sport
        self.dport = packet.dport
        self.seq = packet.seq
        self.ack = packet.ack
        self.dataofs = packet.dataofs
        self.reserved = packet.reserved
        self.tcp_flags = packet["TCP"].flags
        self.window = packet.window
        self.chksum = packet.chksum
        self.urgptr = packet.urgptr
        self.IP = packet["IP"]
        self.TCP = packet["TCP"]
        self.Raw = packet["Raw"]


if __name__ == '__main__':
    src="172.16.64.15"
    dst="124.232.169.221"

    for item in PcapInstance('广告1.pcap'):
        if item.tcp_flags!='PA':print(repr(item))
        # if (item.src==src and item.dst==dst) or (item.src==dst and item.dst==src):
        #
        #     print(item.tcp_flags)
        #     print(item.tcp_flags.value)
        #     print(item.tcp_flags.names)
        #     print(item.tcp_flags.multi)

            # print(type(item.tcp_flags))
            # print(repr(item.IP))
