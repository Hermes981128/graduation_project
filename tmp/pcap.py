'''
 -*- coding: utf-8 -*-
 @Time    : 2021/11/8 21:59
 @Author  : Yun981128
 @Email   : yun981128@gmail.com
 @File    : pcap.py
 @Software: PyCharm
'''

from Logging import log
from winpcapy import WinPcapDevices

logger = log()
logger.debug('This is debug message')
logger.info('This is info message')
logger.warning('This is warning message')

logger.info("当前机器上有以下网卡")
logger.info(WinPcapDevices.list_devices())
print(type(WinPcapDevices.list_devices()))
for item in WinPcapDevices.list_devices().items():
    print(item)

def packet_callback(win_pcap, param, header, pkt_data):
    # Assuming IP (for real parsing use modules like dpkt)
    ip_frame = pkt_data[14:]
    # Parse ips
    src_ip = ".".join([str(ord(b)) for b in ip_frame[0xc:0x10]])
    dst_ip = ".".join([str(ord(b)) for b in ip_frame[0x10:0x14]])
    print("%s -> %s" % (src_ip, dst_ip))


# WinPcapUtils.capture_on("*Ethernet*", packet_callback)


import pcap
import dpkt



def process_packet(ptime, packet):
    tem = dpkt.ethernet.Ethernet(packet)
    if tem.data.data.__class__.__name__ == 'TCP':
        http_data = tem.data.data.data
        if len(http_data) > 0:
            if http_data.startswith(b"HTTP"):
                # http response
                response = dpkt.http.Response(http_data)
                pass
            else:
                # http request
                req = dpkt.http.Request(http_data)
                host = str(req.headers["host"])
                cookie = str(req.headers["cookie"])
                path = str(req.uri)
                if host.index("qianka.com"):
                    logging.info("QianKa message:" + host + cookie + path)
                pass


def print_http_packet(ts, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    # This is an oversimplification - IP packets can fragment if an MTU in the path is smaller than the MTU of the LAN
    # Also, this changes a little bit with IPv6.  To tell the difference between IPv4 and IPv6, you have to look
    # at the ethertype field, which is given by http://www.iana.org/assignments/ethernet-numbers.  IPv4 is 0x800 or 2048
    # and IPv6 is 0x86DD or 34525
    tcp = ip.data
    # This is an oversimplification - this is true if and only if the protocol field of the IP packet is 6.
    # See http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml for details of protocol numbers.
    # See http://tools.ietf.org/html/rfc791 for details on IPv4

    # If the destination port is 80 and there is data in the packet, then probably this is an HTTP request.
    # TO be certain, there should
    # be a TCP finite state machine in here.
    if tcp.dport == 80 and len(tcp.data) > 0:
        http_req = dpkt.http.Request(tcp.data)
        print("URI is ", http_req.uri)
        for header in http_req.headers.keys():
            print(header, http_req.headers[header])
        # ['_Request__methods', '_Request__proto', '__class__', '__delattr__', '__dict__', '__doc__',
        #  '__format__', '__getattribute__', '__getitem__', '__hash__', '__hdr_defaults__', '__init__',
        #  '__len__', '__metaclass__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
        # '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'body', 'data',
        # 'headers', 'method', 'pack', 'pack_hdr', 'unpack', 'uri', 'version']
        print("method is ", http_req.method)
        # 'body', 'data', 'headers', 'method', 'pack', 'pack_hdr', 'unpack', 'uri', 'version'
        print("HTTP headers, packed ", http_req.pack())
        print("HTTP version", http_req.version)
        print("HTTP data ", http_req.data)  # I think this is valid if the method is POST
    if tcp.sport == 80 and len(tcp.data) > 0:
        try:
            http = dpkt.http.Response(tcp.data)
            print("HTTP version is ", http.version)
            print("Status code is ", http.status)
            print("Status reason ", http.reason)
            for header in http.headers.keys():
                print(header, http.headers[header])
                # print "date", http.headers['date']
                # print "accept-ranges", http.headers['accept-ranges']
                # print "content-type", http.headers['content-type']
                #            print "connection", http.headers['connection']
                #            print "server", http.headers['server']
        except dpkt.dpkt.UnpackError:
            print("Encounted an unpacking error")




if __name__ == '__main__':

    for ptime, packet in sniffer:
        try:
            # process_packet(ptime, packet)
            print_http_packet(ptime, packet)
        except Exception as e:
            # print(e)
            pass
