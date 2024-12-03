#encoding:utf-8
from distutils.log import error
import sys
import os
import time
import struct
import json
import pickle

sys.path.append(os.path.expandvars('/usr/local/sde/lib/python2.7/site-packages/tofino'))

from bfrt_grpc import client

GRPC_CLIENT = client.ClientInterface(grpc_addr="localhost:50052", client_id=0,device_id=0, is_master=True)
bfrt_info = GRPC_CLIENT.bfrt_info_get(p4_name=None)
GRPC_CLIENT.bind_pipeline_config(p4_name=bfrt_info.p4_name)

if bfrt_info.p4_name!='IBLT':
    sys.stderr.write("P4 program mismatch: driver reports currently running '%s' \n"% bfrt_info.p4_name)
    sys.exit(-1)



def readRegister():
    target = client.Target()
    BF_0_row0_table = bfrt_info.table_get("SwitchEgress.BF_0_row0")
    BF_0_row1_table = bfrt_info.table_get("SwitchEgress.BF_0_row1")
    BF_1_row0_table = bfrt_info.table_get("SwitchEgress.BF_1_row0")
    BF_1_row1_table = bfrt_info.table_get("SwitchEgress.BF_1_row1")
    # 中IBLT row0
    IBLT_0_srcIP_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_srcIP_row0")
    IBLT_0_dstIP_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_dstIP_row0")
    IBLT_0_ports_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_ports_row0")
    IBLT_0_pktCnt_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_pktCnt_row0")
    IBLT_0_proto_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_proto_row0")
    IBLT_0_flowCnt_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_0_flowCnt_row0")

    # 中IBLT row1
    IBLT_0_srcIP_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_srcIP_row1")
    IBLT_0_dstIP_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_dstIP_row1")
    IBLT_0_ports_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_ports_row1")
    IBLT_0_pktCnt_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_pktCnt_row1")
    IBLT_0_proto_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_proto_row1")
    IBLT_0_flowCnt_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_0_flowCnt_row1")



    # 高IBLT row0
    IBLT_1_srcIP_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_srcIP_row0")
    IBLT_1_dstIP_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_dstIP_row0")
    IBLT_1_ports_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_ports_row0")
    IBLT_1_pktCnt_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_pktCnt_row0")
    IBLT_1_proto_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_proto_row0")
    IBLT_1_flowCnt_row0_table = bfrt_info.table_get("SwitchEgress.IBLT_1_flowCnt_row0")

    # 高IBLT row1
    IBLT_1_srcIP_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_srcIP_row1")
    IBLT_1_dstIP_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_dstIP_row1")
    IBLT_1_ports_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_ports_row1")
    IBLT_1_pktCnt_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_pktCnt_row1")
    IBLT_1_proto_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_proto_row1")
    IBLT_1_flowCnt_row1_table = bfrt_info.table_get("SwitchEgress.IBLT_1_flowCnt_row1")


    pipe_No = 0

    # time.sleep(1)
    print('-----start-----')

    IBLT_0_srcIP_row0_table.operations_execute(target, 'Sync')
    #read all context of a IndirectRegister
    resp = IBLT_0_srcIP_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_srcIP_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_srcIP_row0[i].append(data_dict["SwitchEgress.IBLT_0_srcIP_row0.f1"][i])
    # IBLT_0_Count = IBLT_0_srcIP_row0[1].count(0)
    # print(IBLT_0_Count)
    # if IBLT_0_Count==1024:
    #     return 1
    resp = IBLT_0_dstIP_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_dstIP_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_dstIP_row0[i].append(data_dict["SwitchEgress.IBLT_0_dstIP_row0.f1"][i])


    resp = IBLT_0_ports_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_ports_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_ports_row0[i].append(data_dict["SwitchEgress.IBLT_0_ports_row0.f1"][i])



    resp = IBLT_0_pktCnt_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_pktCnt_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_pktCnt_row0[i].append(data_dict["SwitchEgress.IBLT_0_pktCnt_row0.f1"][i])

    resp = IBLT_0_proto_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_proto_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_proto_row0[i].append(data_dict["SwitchEgress.IBLT_0_proto_row0.f1"][i])

    resp = IBLT_0_flowCnt_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_flowCnt_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_flowCnt_row0[i].append(data_dict["SwitchEgress.IBLT_0_flowCnt_row0.f1"][i])



    resp = IBLT_0_srcIP_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_srcIP_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_srcIP_row1[i].append(data_dict["SwitchEgress.IBLT_0_srcIP_row1.f1"][i])

    resp = IBLT_0_dstIP_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_dstIP_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_dstIP_row1[i].append(data_dict["SwitchEgress.IBLT_0_dstIP_row1.f1"][i])


    resp = IBLT_0_ports_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_ports_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_ports_row1[i].append(data_dict["SwitchEgress.IBLT_0_ports_row1.f1"][i])



    resp = IBLT_0_pktCnt_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_pktCnt_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_pktCnt_row1[i].append(data_dict["SwitchEgress.IBLT_0_pktCnt_row1.f1"][i])

    resp = IBLT_0_proto_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_proto_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_proto_row1[i].append(data_dict["SwitchEgress.IBLT_0_proto_row1.f1"][i])

    resp = IBLT_0_flowCnt_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_0_flowCnt_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_0_flowCnt_row1[i].append(data_dict["SwitchEgress.IBLT_0_flowCnt_row1.f1"][i])


    #read all context of a IndirectRegister
    resp = IBLT_1_srcIP_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_srcIP_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_srcIP_row0[i].append(data_dict["SwitchEgress.IBLT_1_srcIP_row0.f1"][i])

    resp = IBLT_1_dstIP_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_dstIP_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_dstIP_row0[i].append(data_dict["SwitchEgress.IBLT_1_dstIP_row0.f1"][i])


    resp = IBLT_1_ports_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_ports_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_ports_row0[i].append(data_dict["SwitchEgress.IBLT_1_ports_row0.f1"][i])



    resp = IBLT_1_pktCnt_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_pktCnt_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_pktCnt_row0[i].append(data_dict["SwitchEgress.IBLT_1_pktCnt_row0.f1"][i])

    resp = IBLT_1_proto_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_proto_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_proto_row0[i].append(data_dict["SwitchEgress.IBLT_1_proto_row0.f1"][i])

    resp = IBLT_1_flowCnt_row0_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_flowCnt_row0 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_flowCnt_row0[i].append(data_dict["SwitchEgress.IBLT_1_flowCnt_row0.f1"][i])



    resp = IBLT_1_srcIP_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_srcIP_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_srcIP_row1[i].append(data_dict["SwitchEgress.IBLT_1_srcIP_row1.f1"][i])

    resp = IBLT_1_dstIP_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_dstIP_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_dstIP_row1[i].append(data_dict["SwitchEgress.IBLT_1_dstIP_row1.f1"][i])


    resp = IBLT_1_ports_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_ports_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_ports_row1[i].append(data_dict["SwitchEgress.IBLT_1_ports_row1.f1"][i])



    resp = IBLT_1_pktCnt_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_pktCnt_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_pktCnt_row1[i].append(data_dict["SwitchEgress.IBLT_1_pktCnt_row1.f1"][i])

    resp = IBLT_1_proto_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_proto_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_proto_row1[i].append(data_dict["SwitchEgress.IBLT_1_proto_row1.f1"][i])

    resp = IBLT_1_flowCnt_row1_table.entry_get(
                target,
                flags={"from_hw": True})
    data_list = list(resp)

    #[[pipe0_list], [pipe1_list]]
    IBLT_1_flowCnt_row1 = [[], []]

    for data_instance in data_list:
        data_dict = data_instance[0].to_dict()
        for i in range(2):
            IBLT_1_flowCnt_row1[i].append(data_dict["SwitchEgress.IBLT_1_flowCnt_row1.f1"][i])
    if IBLT_0_srcIP_row0[1].count(0)==1024:
        print("no new file produce!")
        return 1
    else:
        fileStr = "./grpc_pkl/"
        filename = fileStr + str(time.time()) + ".pkl"
        f = open(filename, 'wb+')
        pickle.dump((IBLT_0_srcIP_row0[1],
                IBLT_0_srcIP_row1[1],
                IBLT_0_dstIP_row0[1],
                IBLT_0_dstIP_row1[1],
                IBLT_0_ports_row0[1],
                IBLT_0_ports_row1[1],
                IBLT_0_proto_row0[1],
                IBLT_0_proto_row1[1],
                IBLT_0_flowCnt_row0[1],
                IBLT_0_flowCnt_row1[1],
                IBLT_0_pktCnt_row0[1],
                IBLT_0_pktCnt_row1[1],
                IBLT_1_srcIP_row0[1],
                IBLT_1_srcIP_row1[1],
                IBLT_1_dstIP_row0[1],
                IBLT_1_dstIP_row1[1],
                IBLT_1_ports_row0[1],
                IBLT_1_ports_row1[1],
                IBLT_1_proto_row0[1],
                IBLT_1_proto_row1[1],
                IBLT_1_flowCnt_row0[1],
                IBLT_1_flowCnt_row1[1],
                IBLT_1_pktCnt_row0[1],
                IBLT_1_pktCnt_row1[1]), f)
        f.close()
        # print(os.path.getsize(f))
        BF_0_row0_table.entry_del(target)
        BF_0_row1_table.entry_del(target)
        BF_1_row0_table.entry_del(target)
        BF_1_row1_table.entry_del(target)
        # 中IBLT row0
        IBLT_0_srcIP_row0_table.entry_del(target)
        IBLT_0_dstIP_row0_table.entry_del(target)
        IBLT_0_ports_row0_table.entry_del(target)
        IBLT_0_pktCnt_row0_table.entry_del(target)
        IBLT_0_proto_row0_table.entry_del(target)
        IBLT_0_flowCnt_row0_table.entry_del(target)

        # 中IBLT row1
        IBLT_0_srcIP_row1_table.entry_del(target)
        IBLT_0_dstIP_row1_table.entry_del(target)
        IBLT_0_ports_row1_table.entry_del(target)
        IBLT_0_pktCnt_row1_table.entry_del(target)
        IBLT_0_proto_row1_table.entry_del(target)
        IBLT_0_flowCnt_row1_table.entry_del(target)



        # 高IBLT row0
        IBLT_1_srcIP_row0_table.entry_del(target)
        IBLT_1_dstIP_row0_table.entry_del(target)
        IBLT_1_ports_row0_table.entry_del(target)
        IBLT_1_pktCnt_row0_table.entry_del(target)
        IBLT_1_proto_row0_table.entry_del(target)
        IBLT_1_flowCnt_row0_table.entry_del(target)

        # 高IBLT row1
        IBLT_1_srcIP_row1_table.entry_del(target)
        IBLT_1_dstIP_row1_table.entry_del(target)
        IBLT_1_ports_row1_table.entry_del(target)
        IBLT_1_pktCnt_row1_table.entry_del(target)
        IBLT_1_proto_row1_table.entry_del(target)
        IBLT_1_flowCnt_row1_table.entry_del(target)

        print("clear all")
        # print("cost time: ", time_delta, "ms")
        print('-----end-----')

def main():
    while 1:
        count = readRegister()
        if count == 1:
            print("No IBLT data!")
            # time.sleep(1)

if __name__ == '__main__':
    main()

# filename = "IBLT_bytes_row0.json"
# f = open(filename, 'w+')
# json.dump(IBLT_reg[0], fp = f, indent = 2)



