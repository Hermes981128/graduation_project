'''
 -*- coding: utf-8 -*-
 @Time    : 2021/11/8 21:38
 @Author  : Yun981128
 @Email   : yun981128@gmail.com
 @File    : forwarding_data.py
 @Software: PyCharm
'''

from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
import dpkt
import time



def packet_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    # # 判断是否为IP数据报
    if not isinstance(eth.data, dpkt.ip.IP):
        print("Non IP packet type not supported ", eth.data.__class__.__name__)
        return
    # 抓IP数据包
    packet = eth.data
    # 取出分片信息
    # DF：Don't Fragment，“不分片”位，如果将这一比特置1，IP层将不对数据报进行分片。
    df = bool(packet.off & dpkt.ip.IP_DF)
    # MF：More Fragment，“更多的片”，除了最后一片外，其他每个组成数据报的片都要把该比特置1。
    mf = bool(packet.off & dpkt.ip.IP_MF)
    offset = packet.off & dpkt.ip.IP_OFFMASK


    # 输出数据包信息：time,src,dst,protocol,length,ttl,df,mf,offset,checksum
    output1 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))}
    output2 = {'src': '%d.%d.%d.%d' % tuple(packet.src), 'dst': '%d.%d.%d.%d' % tuple(packet.dst)}
    output3 = {'protocol': packet.p, 'len': packet.len, 'ttl': packet.ttl}
    output4 = {'df': df, 'mf': mf, 'offset': offset, 'checksum': packet.sum}
    print(packet.data)
    print("="*50)
    print(output1)
    print(output2)
    print(output3)
    print(output4)


if __name__ == '__main__':
    print("开始运行")
    print("网卡列表：")
    list_device = WinPcapDevices.list_devices()
    device_names = []
    for device in list_device.items():
        print(device)
        device_names.append(device[0])

    device_name = device_names[int(input("请输入抓包网卡序号：")) - 1]
    WinPcapUtils.capture_on_device_name(device_name=device_name, callback=packet_callback)
