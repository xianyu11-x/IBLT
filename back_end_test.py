# encoding:utf-8
#!/usr/bin/env python
from cgi import FieldStorage
import sys
import struct
import os
import time
import pickle
import crcmod
import zlib
import socket
import random
import struct
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
import readline

#crc16/IBM
crc16Ibm = crcmod.mkCrcFun(0x18005, rev = True, initCrc = 0x0000, xorOut = 0000)
#统计镜像的数据包的数量
count = 0

#给count值每次加一
def addCount():
    global count
    count+=1

def saveCount():
    global count
    # 打开一个文件
    fo = open("count.txt", "a")
    fo.write(str(count))
    fo.write('\n')
    # 关闭打开的文件
    fo.close()

#给count值赋值为0
def clearCount():
    global count
    saveCount()
    print(count)# 输出count值调试使用
    count=0


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class flowIBLT:
    def __init__(self, col, row = 2):
        a = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        self.reg = [[a] * col for i in range(row)]
        self.BF = [[0] * col for i in range(row)]
        self.col = col
        self.row = row

    '''
    输入bigEndBytes为五元组13bytes
    IBLT每槽位分为flowXOR，flowCount，pktCount
    flowXOR    flowCount   pktCount
    [0:13]     [13:14]     [14:16]
    
    flowXOR: srcIP dstIP sport  dport   proto
             [0:4] [4:8] [8:10] [10:12] [12:13]
    BF检测是否新流，新流全部更新，否则只更新pktCount
    '''
    def insert(self, bigEndBytes):
        crc_32 = zlib.crc32(bigEndBytes) % self.col
        crc_16 = crc16Ibm(bigEndBytes) % self.col
        BFBool = self.BF[0][crc_32] and self.BF[1][crc_16]
        self.BF[0][crc_32] = 1
        self.BF[1][crc_16] = 1

        indexList = [crc_32, crc_16]
        for i in range(0, self.row):
            # pktCount，bytes转int处理
            temp3 = self.reg[i][indexList[i]][14: 16]
            pCnt = int.from_bytes(temp3, byteorder='big', signed=False)
            pCnt += 1
            pRnt = pCnt.to_bytes(4, byteorder='big')

            # 新流
            if not BFBool:
                # flowXOR，bytes转list处理
                temp1 = self.reg[i][indexList[i]][0: 13]
                # bytes转int组成的list
                xorX = list(temp1)
                xorY = list(bigEndBytes)
                for k in range(0, len(xorX)):
                    xorY[k] = xorX[k] ^ xorY[k]
                # list转bytes
                XORRnt = bytes(xorY)

                # flowCount，bytes转int处理
                temp2 = self.reg[i][indexList[i]][13: 14]
                fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
                fCnt += 1
                fRnt = fCnt.to_bytes(2, byteorder='big')

                self.reg[i][indexList[i]] = XORRnt + fRnt + pRnt
            #旧流
            else:
                self.reg[i][indexList[i]] = self.reg[i][indexList[i]][0: 14] + pRnt

    '''
    解析pure slot流信息，返回元组(流字符串, 包数量)
    flowXOR: srcIP dstIP sport  dport   proto
             [0:4] [4:8] [8:10] [10:12] [12:13]
    
    #TCP,41.177.26.91:80,68.157.168.194:65003: 536
    '''
    def decodePureSlot(self, slotBytes):
        protoList = {1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP"}
        flowXOR = slotBytes[0: 13]
        srcIP = socket.inet_ntoa(flowXOR[0: 4])
        sport = int.from_bytes(flowXOR[8: 10], byteorder='big', signed=False)
        dstIP = socket.inet_ntoa(flowXOR[4: 8])
        dport = int.from_bytes(flowXOR[10: 12], byteorder='big', signed=False)
        proto = int.from_bytes(flowXOR[12: 13], byteorder='big', signed=False)
        protoStr = protoList[proto]

        flowStr = ""
        flowStr += protoStr + "," + srcIP + ":" + \
                  str(sport) + "-->" + \
                  dstIP + ":" + str(dport)

        pktVal = int.from_bytes(slotBytes[14: 16], byteorder='big', signed=False)
        return (flowStr, pktVal)

    #迭代解码IBLT
    def query(self):
        #格式与flowStat相同，字符串: 个数
        flowInfo = {}

        #为1：存在pure slot可以解码。为0：无法继续解码
        decodeFlag = 1
        while decodeFlag:
            decodeFlag = 0
            # #调试用
            # try_count = 0
            # try_list = []
            # for i in range(0, self.row):
            #     for j in range(0, self.col):
            #         temp2 = self.reg[i][j][13: 15]
            #         fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
            #         if fCnt > 0:
            #             try_count += 1
            #             try_list.append(fCnt)
            # print("本轮待解析槽位: %d" %try_count)
            # print(try_list)

            #遍历整个reg
            for i in range(0, self.row):
                for j in range(0, self.col):
                    temp2 = self.reg[i][j][13: 14]
                    fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
                    if fCnt == 1:
                        # print('新一轮解析, 位置: row%d, col%d' %(i, j))
                        decodeFlag = 1
                        #解码信息存入flowInfo
                        flowTup = self.decodePureSlot(self.reg[i][j])
                        keyStr = flowTup[0]
                        valStr = flowTup[1]
                        # print(flowTup)
                        if keyStr in flowInfo:
                            flowInfo[keyStr] += valStr
                        else:
                            flowInfo[keyStr] = valStr

                        #消去流
                        temp1 = self.reg[i][j][0: 13]
                        temp3 = self.reg[i][j][14: 16]
                        count = int.from_bytes(temp3, byteorder='big', signed=False)

                        crc_32 = zlib.crc32(temp1) % self.col
                        crc_16 = crc16Ibm(temp1) % self.col
                        indexList = [crc_32, crc_16]

                        # print('消去位置row0: row0, col%d' %crc_32)
                        # print('消去位置row1: row1, col%d' %crc_16)
                        if j != indexList[i]:
                            print('无效条目！清空该槽')
                            a = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
                            self.reg[i][j] = a
                            break
                            


                        for i in range(0, self.row):
                            # bytes转int组成的list
                            xorX = list(temp1)
                            xorY = list(self.reg[i][indexList[i]][0: 13])
                            for k in range(0, len(xorX)):
                                xorY[k] = xorX[k] ^ xorY[k]
                            # list转bytes
                            XORRnt = bytes(xorY)

                            # flowCount，bytes转int处理
                            temp2 = self.reg[i][indexList[i]][13: 14]
                            fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
                            if fCnt < 1:
                                fCnt = 0
                            else:
                                fCnt -= 1
                            #print('fRnt: %d' %fCnt)
                            fRnt = fCnt.to_bytes(2, byteorder='big')

                            #pktCount，bytes转int处理
                            temp3 = self.reg[i][indexList[i]][14: 16]
                            pCnt = int.from_bytes(temp3, byteorder='big', signed=False)
                            if pCnt < count:
                                pCnt = 0
                            else:
                                pCnt -= count
                            pRnt = pCnt.to_bytes(4, byteorder='big')

                            self.reg[i][indexList[i]] = XORRnt + fRnt + pRnt
                            #print(self.reg[i][indexList[i]])
                        break
                if decodeFlag == 1:
                    break
        return flowInfo

    #清除IBLT
    def clean(self):
        self.reg.clear()
        a = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        self.reg = [[a] * self.col for i in range(self.row)]
        self.BF.clear()
        self.BF = [[0] * self.col for i in range(self.row)]


class INT(Packet):
    fields_desc = [ BitField("protocol", 0, 8),
                  BitField("IBLT_bitmap", 0, 8),
                  BitField("medium_index", 0, 16),
                  BitField("high_index", 0, 16),
                  BitField("mediumIBLT_row0", 0, 128),
                  BitField("mediumIBLT_row1", 0, 128),
                  BitField("highIBLT_row0", 0, 128),
                  BitField("highIBLT_row1", 0, 128)]


bind_layers(IP, INT, proto=250)
bind_layers(INT, ICMP, protocol=1)
bind_layers(INT, TCP, protocol=6)
bind_layers(INT, UDP, protocol=17)

mideumIBLT = flowIBLT(1024)
highIBLT = flowIBLT(1024)

# 中IBLT非零列数量
mideum_NZ_Cnt = 0
high_NZ_Cnt = 0

def save_burst_info(flow_dict, type):
    if flow_dict:
        sketchSortedFlows = sorted(flow_dict.items(), key=lambda i: (i[1], i[0]), reverse=True)
        fileStr = ["./medium_dict/", "./high_dict/"]
        filename = fileStr[type] + str(time.time()-14400) + ".json"
        f = open(filename, 'w+')
        json.dump(sketchSortedFlows, fp=f, indent=2)
    
        logStr = ['medium', 'high']
        print("save " + logStr[type] + " info success!")
        if logStr[type]=='high':
            clearCount()

def handle_pkt(pkt):
    #hexdump(pkt)
    #pkt.show2()
    #print("got a packet")
    #pkt.show2()
    if pkt[INT].mediumIBLT_row0 or pkt[INT].mediumIBLT_row1 or pkt[INT].highIBLT_row0 or pkt[INT].highIBLT_row1:
        print('not zero')
        addCount()
        print(pkt[INT].medium_index)
        print(pkt[INT].high_index)
        print('------------')

    if pkt.haslayer(INT):
        bitmap = pkt[INT].IBLT_bitmap
        # 中IBLT
        if bitmap % 2:
            if pkt[INT].mediumIBLT_row0 or pkt[INT].mediumIBLT_row1 or pkt[INT].medium_index == 1023:
                mideumIBLT.reg[0][pkt[INT].medium_index] = pkt[INT].mediumIBLT_row0.to_bytes(16, byteorder='big')
                mideumIBLT.reg[1][pkt[INT].medium_index] = pkt[INT].mediumIBLT_row1.to_bytes(16, byteorder='big')
                if pkt[INT].medium_index == 1023:
                    flowInfo = mideumIBLT.query()
                    if flowInfo:
                        mideumIBLT.clean()
                        save_burst_info(flowInfo, 0)

        # 高IBLT
        if bitmap / 2:
            if pkt[INT].highIBLT_row0 or pkt[INT].highIBLT_row1 or pkt[INT].high_index == 1023:
                highIBLT.reg[0][pkt[INT].high_index] = pkt[INT].highIBLT_row0.to_bytes(16, byteorder='big')
                highIBLT.reg[1][pkt[INT].high_index] = pkt[INT].highIBLT_row1.to_bytes(16, byteorder='big')
                if pkt[INT].high_index == 1023:
                    flowInfo = highIBLT.query()
                    if flowInfo:
                        highIBLT.clean()
                        save_burst_info(flowInfo, 1)


        # int型
        # print(type(pkt[INT].mediumIBLT_row0))
    sys.stdout.flush()


def main():
    if len(sys.argv)<2:
        print ("pass 1 arguments: <veth_name>")
        exit(1)
    
    iface = sys.argv[1]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    
    filter_str = "ip and proto 250"

    sniff(filter='', iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
