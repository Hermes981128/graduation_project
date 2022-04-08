'''
 -*- coding: utf-8 -*-
 @Time    : 2021/11/18 20:38
 @Author  : Yun981128
 @Email   : yun981128@gmail.com
 @File    : test.py
 @Software: PyCharm
'''
import dpkt
from base64 import b64decode
from tool.MysqlCommand import MysqlCommand





if __name__ == '__main__':
    db=MysqlCommand()
    command="select PktData from source_data"
    PktDatas=[item[0] for item in db.execute_with_return(command)]
    for PktData in PktDatas:
        pkt_data=b64decode(PktData)
        eth = dpkt.ethernet.Ethernet(pkt_data)
        print(repr(eth.data))
