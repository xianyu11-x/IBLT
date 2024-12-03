#encoding:utf-8
import sys
import os
import time
import pickle
import crcmod
import zlib
import socket
import random
import struct
import json

#crc16/IBM
crc16Ibm = crcmod.mkCrcFun(0x18005, rev = True, initCrc = 0x0000, xorOut = 0000)


class flowIBLT:
    def __init__(self, col, row = 2):
        a = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        self.reg = [[a] * col for i in range(row)]
        self.BF = [[0] * col for i in range(row)]
        self.col = col
        self.row = row
    '''
    输入bigEndBytes为五元组13bytes
    IBLT每槽位分为flowXOR,flowCount,pktCount
    flowXOR    flowCount   pktCount
    [0:13]     [13:14]     [14:16]
    
    flowXOR: srcIP dstIP sport  dport   proto
             [0:4] [4:8] [8:10] [10:12] [12:13]
    BF检测是否新流,新流全部更新,否则只更新pktCount
    '''
    def insert(self, bigEndBytes):
        crc_32 = zlib.crc32(bigEndBytes) % self.col
        crc_16 = crc16Ibm(bigEndBytes) % self.col
        BFBool = self.BF[0][crc_32] and self.BF[1][crc_16]
        self.BF[0][crc_32] = 1
        self.BF[1][crc_16] = 1

        indexList = [crc_32, crc_16]
        for i in range(0, self.row):
            # pktCount,bytes转int处理
            temp3 = self.reg[i][indexList[i]][14: 16]
            pCnt = int.from_bytes(temp3, byteorder='big', signed=False)
            pCnt += 1
            pRnt = pCnt.to_bytes(4, byteorder='big')

            # 新流
            if not BFBool:
                # flowXOR,bytes转list处理
                temp1 = self.reg[i][indexList[i]][0: 13]
                # bytes转int组成的list
                xorX = list(temp1)
                xorY = list(bigEndBytes)
                for k in range(0, len(xorX)):
                    xorY[k] = xorX[k] ^ xorY[k]
                # list转bytes
                XORRnt = bytes(xorY)

                # flowCount,bytes转int处理
                temp2 = self.reg[i][indexList[i]][13: 14]
                fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
                fCnt += 1
                fRnt = fCnt.to_bytes(2, byteorder='big')

                self.reg[i][indexList[i]] = XORRnt + fRnt + pRnt
            #旧流
            else:
                self.reg[i][indexList[i]] = self.reg[i][indexList[i]][0: 14] + pRnt

    '''
    解析pure slot流信息,返回元组(流字符串, 包数量)
    flowXOR: srcIP dstIP sport  dport   proto
             [0:4] [4:8] [8:10] [10:12] [12:13]
    
    #TCP,41.177.26.91:80,68.157.168.194:65003: 536
    '''
    def decodePureSlot(self, slotBytes):
        protoList = {0: "HOPOPT",1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP"}
        flowXOR = slotBytes[0: 13]
        srcIP = socket.inet_ntoa(flowXOR[0: 4])
        sport = int.from_bytes(flowXOR[8: 10], byteorder='big', signed=False)
        dstIP = socket.inet_ntoa(flowXOR[4: 8])
        dport = int.from_bytes(flowXOR[10: 12], byteorder='big', signed=False)
        proto = int.from_bytes(flowXOR[12: 13], byteorder='big', signed=False)
        if proto == 0:
            print("error")
        protoStr = protoList[proto]

        flowStr = ""
        flowStr += protoStr + "," + srcIP + ":" + \
                  str(sport) + "-->" + \
                  dstIP + ":" + str(dport)

        pktVal = int.from_bytes(slotBytes[14: 16], byteorder='big', signed=False)
        return (flowStr, pktVal)

    #迭代解码IBLT
    def query(self):
        #格式与flowStat相同,字符串: 个数
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
                        #print(self.reg[i][j])
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

                            # flowCount,bytes转int处理
                            temp2 = self.reg[i][indexList[i]][13: 14]
                            fCnt = int.from_bytes(temp2, byteorder='big', signed=False)
                            if fCnt < 1:
                                fCnt = 0
                            else:
                                fCnt -= 1
                            #print('fRnt: %d' %fCnt)
                            fRnt = fCnt.to_bytes(2, byteorder='big')

                            #pktCount,bytes转int处理
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

def saveFile(filename):
    # [[row0], [row1]]
    IBLT_0_srcIP = [[], []]
    IBLT_0_dstIP = [[], []]
    IBLT_0_ports = [[], []]
    IBLT_0_proto = [[], []]
    IBLT_0_flowCnt = [[], []]
    IBLT_0_pktCnt = [[], []]

    IBLT_1_srcIP = [[], []]
    IBLT_1_dstIP = [[], []]
    IBLT_1_ports = [[], []]
    IBLT_1_proto = [[], []]
    IBLT_1_flowCnt = [[], []]
    IBLT_1_pktCnt = [[], []]


    # fileStr = "./grpc_pkl/"
    # filename = fileStr + "IBLT_int.pkl"
    # filename = "IBLT_int.pkl"

    while 1:
        size1 = os.path.getsize(filename)
        time.sleep(0.2)
        size2 = os.path.getsize(filename)
        if size1 == size2 and size1 > 2:
            f = open(filename, 'rb')
            print(f)
        else:
            continue
        # data_arr = ()
        data_arr = pickle.load(f,encoding="bytes")
        if len(data_arr) == 24:
            break
        else:
            print(len(data_arr))
    print(len(data_arr))
    # print(data_arr[0])
    IBLT_0_srcIP[0], IBLT_0_srcIP[1], IBLT_0_dstIP[0], IBLT_0_dstIP[1], IBLT_0_ports[0], IBLT_0_ports[1], IBLT_0_proto[0], IBLT_0_proto[1], IBLT_0_flowCnt[0], IBLT_0_flowCnt[1], IBLT_0_pktCnt[0], IBLT_0_pktCnt[1], IBLT_1_srcIP[0], IBLT_1_srcIP[1], IBLT_1_dstIP[0], IBLT_1_dstIP[1], IBLT_1_ports[0], IBLT_1_ports[1], IBLT_1_proto[0], IBLT_1_proto[1], IBLT_1_flowCnt[0], IBLT_1_flowCnt[1], IBLT_1_pktCnt[0], IBLT_1_pktCnt[1] = data_arr


    # [[row0], [row1]]
    IBLT_0_bytes = [[], []]
    IBLT_1_bytes = [[], []]


    flag_0_array = [0] * 1024
    flag_1_array = [0] * 1024

    res_count = 0
    for i in range(2):
        for j in range(1024):
            srcIP0 = IBLT_0_srcIP[i][j].to_bytes(4, byteorder='big')
            dstIP0 = IBLT_0_dstIP[i][j].to_bytes(4, byteorder='big')
            ports0 = IBLT_0_ports[i][j].to_bytes(4, byteorder='big')
            sport0 = ports0[0:2]
            dport0 = ports0[2:4]
            proto0 = IBLT_0_proto[i][j].to_bytes(1, byteorder='big')
            flowCnt0 = IBLT_0_flowCnt[i][j].to_bytes(1, byteorder='big')
            if IBLT_0_flowCnt[i][j] > 0:
                flag_0_array[j] = 1

            pktCnt0 = IBLT_0_pktCnt[i][j].to_bytes(2, byteorder='big')

            tup0 = srcIP0 + dstIP0 + sport0 + dport0 + proto0 + flowCnt0 + pktCnt0
            IBLT_0_bytes[i].append(tup0)


            srcIP1 = IBLT_1_srcIP[i][j].to_bytes(4, byteorder='big')
            dstIP1 = IBLT_1_dstIP[i][j].to_bytes(4, byteorder='big')
            ports1 = IBLT_1_ports[i][j].to_bytes(4, byteorder='big')
            sport1 = ports1[0:2]
            dport1 = ports1[2:4]
            proto1 = IBLT_1_proto[i][j].to_bytes(1, byteorder='big')
            flowCnt1 = IBLT_1_flowCnt[i][j].to_bytes(1, byteorder='big')
            if IBLT_1_flowCnt[i][j] > 0:
                flag_1_array[j] = 1

            pktCnt1 = IBLT_1_pktCnt[i][j].to_bytes(2, byteorder='big')

            tup1 = srcIP1 + dstIP1 + sport1 + dport1 + proto1 + flowCnt1 + pktCnt1
            IBLT_1_bytes[i].append(tup1)

    for i in flag_0_array:
        if i != 0:
            res_count += 1
    print('中拥塞IBLT非0列个数: %d' %res_count)


    for i in flag_1_array:
        if i != 0:
            res_count += 1
    print('高拥塞IBLT非0列个数: %d' %res_count)


    fIBLT0 = flowIBLT(1024)
    fIBLT0.reg = IBLT_0_bytes
    flowInfo0 = fIBLT0.query()
    sketchSortedFlows0 = sorted(flowInfo0.items(), key=lambda i: (i[1], i[0]), reverse=True)
    # print(sketchSortedFlows)

    fileStr0 = "./medium_grpc/"
    filename0 = fileStr0 +str(time.time()-14400) + ".json"
    # filename0 = "IBLT_res_0.json"
    f0 = open(filename0, 'w+')
    json.dump(sketchSortedFlows0, fp=f0, indent=2)

    fIBLT1 = flowIBLT(1024)
    fIBLT1.reg = IBLT_1_bytes
    flowInfo1 = fIBLT1.query()
    sketchSortedFlows1 = sorted(flowInfo1.items(), key=lambda i: (i[1], i[0]), reverse=True)
    # print(sketchSortedFlows)

    fileStr1 = "./high_grpc/"
    filename1 = fileStr1 +str(time.time()-14400) + ".json"
    # filename1 = "IBLT_res_1.json"
    f1 = open(filename1, 'w+')
    json.dump(sketchSortedFlows1, fp=f1, indent=2)



def visitDir(path):
    if not os.path.isdir(path):
        print('Error: "', path, '" is not a directory or does not exist.')
        return
    else:
        temp = 0
        try:
            for lists in os.listdir(path):
                # sub_path = os.path.join(path, lists)
                temp += 1
            return temp
        except:
            pass

def main():
    last = 0
    # fileStr = "./grpc_pkl/"
    # filename = fileStr + "IBLT_int.pkl"
    path = './grpc_pkl/'
    while 1:
        current = visitDir(path)
        if(current>last):
            lists = os.listdir(path)
            lists.sort(key=lambda x:os.path.getmtime((path+x)))
            print(lists)
            for i in range(current-last-1,-1,-1):
                file_new = os.path.join(path, lists[-1-i])
                if file_new.endswith('.pkl'):
                    # print(os.path.getsize(file_new)
                    print(file_new)
                    saveFile(file_new)
            last = current
        else:
            print("No new file!")
        time.sleep(1)

if __name__ == '__main__':
    main()