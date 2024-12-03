import sys
import os
import time
sys.path.append(os.path.expandvars('/usr/local/sde/lib/python2.7/site-packages/tofino'))

from bfrt_grpc import client

GRPC_CLIENT = client.ClientInterface(grpc_addr="localhost:50052", client_id=0,device_id=0)
bfrt_info = GRPC_CLIENT.bfrt_info_get(p4_name=None)
GRPC_CLIENT.bind_pipeline_config(p4_name=bfrt_info.p4_name)

if bfrt_info.p4_name!='IBLT_IN':
    sys.stderr.write("P4 program mismatch: driver reports currently running '%s' \n"% bfrt_info.p4_name)
    sys.exit(-1)


def program_tb_congest_decide_table(table, target, mat_Pri, qdepth_start, qdepth_end, Con_type):
    print("Programming tb_congest_decide_table for congest detection")
    
    key_list = []
    data_list = []
    key_list.append(table.make_key([client.KeyTuple('$MATCH_PRIORITY', mat_Pri),
                                    client.KeyTuple('eg_intr_md.deq_qdepth', 
                                                    low = qdepth_start, 
                                                    high = qdepth_end)]))
    
    data_list.append(table.make_data([client.DataTuple('type', Con_type)],
                                     "SwitchEgress.set_congest_type"))
    table.entry_add(target, key_list, data_list)


def program_tb_L2_fwd(table, target, dmac, dest_port):
    print("Programming tb_L2_fwd for L2 FIB")
    
    key_list = []
    data_list = []
    
    key_list.append(table.make_key([client.KeyTuple('hdr.ethernet.dst_addr', client.mac_to_bytes(dmac))]))
    
    data_list.append(table.make_data([client.DataTuple('dest_port', dest_port)],
                                     "SwitchIngress.route_to_port"))
    try:
        table.entry_add(target, key_list, data_list)
    except Exception as e:
        print("exception: %s" %(e))


def program_tb_p2p_fwd(table, target, ingress_port, dest_port):
    print("Programming tb_p2p_fwd for port-to-port forward")
    
    key_list = []
    data_list = []
    
    key_list.append(table.make_key([client.KeyTuple('ig_intr_md.ingress_port', ingress_port)]))
    
    data_list.append(table.make_data([client.DataTuple('dest_port', dest_port)],
                                     "SwitchIngress.route_to_port"))
    table.entry_add(target, key_list, data_list)

mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
target = client.Target()


type1_sid = 33
type2_sid = 42

type1_port = 66
type2_port = 4
cpu_port = 64
max_len = 128    #Mirror_h(70) + Ether(14) + IP (20) + TCP (20) = 128 bytes
#common ucast_egress_port mirror
'''
print("Programming clone_e2e mirror session: %d for the high congest pkt..." % type2_sid)
print("truncation max length: " + str(max_len) + "      mirror port: " + str(type2_port))
mirror_cfg_table.entry_add(
    target,
    [mirror_cfg_table.make_key([client.KeyTuple('$sid', type2_sid)])],
    [mirror_cfg_table.make_data([client.DataTuple('$direction', str_val="EGRESS"),
                                 client.DataTuple('$ucast_egress_port', type2_port),
                                 client.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                 client.DataTuple('$session_enable', bool_val=True),
                                 client.DataTuple('$max_pkt_len', max_len)],
                                '$normal')]
)

print("Programming clone_e2e mirror session: %d for the medium congest pkt..." % type1_sid)
print("truncation max length: " + str(max_len) + "      mirror port: " + str(type1_port))
mirror_cfg_table.entry_add(
    target,
    [mirror_cfg_table.make_key([client.KeyTuple('$sid', type1_sid)])],
    [mirror_cfg_table.make_data([client.DataTuple('$direction', str_val="EGRESS"),
                                 client.DataTuple('$ucast_egress_port', type1_port),
                                 client.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                 client.DataTuple('$session_enable', bool_val=True),
                                 client.DataTuple('$max_pkt_len', max_len)],
                                '$normal')]
)
'''

#cpu port is known, config ucast_egress_port-->cpu_port, direct mirror to cpu port
#don't know cpu port, config copy_to_cpu-->true, icos_for_copy_to_cpu-->0, extra copy a pkt to cpu
print("Programming e2e copy-to-cpu mirror session: %d for test..." % type1_sid)
print("truncation max length: " + str(max_len) + "      mirror port: " + str(type1_port))
mirror_cfg_table.entry_add(
    target,
    [mirror_cfg_table.make_key([client.KeyTuple('$sid', type1_sid)])],
    [mirror_cfg_table.make_data([client.DataTuple('$direction', str_val="EGRESS"),
                                 client.DataTuple('$ucast_egress_port', type1_port),
                                 client.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                 client.DataTuple('$session_enable', bool_val=True),
                                 #client.DataTuple('$max_pkt_len', max_len),
                                 client.DataTuple('$copy_to_cpu', bool_val=False),
                                 client.DataTuple('$icos_for_copy_to_cpu', 0)],
                                '$normal')]
)


#L2 FIB
tb_L2_fwd = bfrt_info.table_get("SwitchIngress.L2_fwd")
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:1B:21:BA:BC:D8",
                  155)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:1B:21:BA:BD:D2",
                  137)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:1B:21:BA:BD:14",
                  139)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:a0:c9:00:00:00",
                  66)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "34:12:78:56:01:00",
                  67)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:1b:21:bd:df:27",
                  175)
program_tb_L2_fwd(tb_L2_fwd,
                  target,
                  "00:1b:21:bd:dc:4b",
                  191)

#p2p forward
tb_p2p_fwd = bfrt_info.table_get("SwitchIngress.p2p_fwd")




tb_congest_decide_table = bfrt_info.table_get("SwitchEgress.tb_congest_decide")

program_tb_congest_decide_table(tb_congest_decide_table,
                         target,
                         0,
                         0,
                         200,
                         0)
program_tb_congest_decide_table(tb_congest_decide_table,
                         target,
                         0,
                         200,
                         800,
                         1)
program_tb_congest_decide_table(tb_congest_decide_table,
                         target,
                         0,
                         800,
                         50000,
                         2)



