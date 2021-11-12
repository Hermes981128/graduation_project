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


# from scapy.utils import PcapReader


class PcapInstance():
    def __init__(self, path: str):
        self.packets = scapy.rdpcap(path)
        self.packet_num=len(self.packets)
        self.index = 0
    def __getitem__(self, item):
        if self.index >=self.packet_num:
            raise StopIteration('停止遍历')  # 抛出异常
        self.index = self.index + 1
        return PacketInstance(self.packets[self.index])

class PacketInstance():
    def __init__(self, packet):
        self.version=packet.version
        self.ihl=packet.ihl
        self.tos=packet.tos
        self.len= packet.len
        self.id=packet.id
        self.flags=packet.flags
        self.frag=packet.frag
        self.ttl=packet.ttl
        self.proto=packet.proto
        self.chksum=packet.chksum
        self.src=packet.src
        self.dst=packet.dst
        self.sport=packet.sport
        self.dport=packet.dport
        self.seq=packet.seq
        self.ack=packet.ack
        self.dataofs=packet.dataofs
        self.reserved=packet.reserved
        self.flags=packet.flags
        self.window=packet.window
        self.chksum=packet.chksum
        self.urgptr=packet.urgptr
        self.IP=packet[0]
        self.TCP=packet[1]
        self.Raw=packet[2]



if __name__ == '__main__':
    print(PcapInstance('红豆.pcap').packet_num)
    for item in PcapInstance('红豆.pcap'):
        print(repr(item.Raw.load))