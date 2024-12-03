import logging
import subprocess
import time
import sys
import os
from ptf.thriftutils import *
import ptf.testutils as testutils
from p4testutils.misc_utils import *
import bfrt_grpc.client as gc
grpc_client=gc.ClientInterface(grpc_addr="localhost:50052",client_id=0,device_id=0)
bfrt_info=grpc_client.bfrt_info_get(p4_name=None)
grpc_client.bind_pipeline_config(p4_name=bfrt_info.p4_name)

def pgen_timer_hdr_to_dmac(pipe_id, app_id, batch_id, packet_id):
    """
    Given the fields of a 6-byte packet-gen header return an Ethernet MAC address
    which encodes the same values.
    """
    pipe_shift = 3
    return '%02x:00:%02x:%02x:%02x:%02x' % ((pipe_id << pipe_shift) | app_id,
                                            batch_id >> 8,
                                            batch_id & 0xFF,
                                            packet_id >> 8,
                                            packet_id & 0xFF)

def pgen_port(pipe_id):
    """
    Given a pipe return a port in that pipe which is usable for packet
    generation.  Note that Tofino allows ports 68-71 in each pipe to be used for
    packet generation while Tofino2 allows ports 0-7.  This example will use
    either port 68 or port 6 in a pipe depending on chip type.
    """
    pipe_local_port = 68
    return make_port(pipe_id, pipe_local_port)

def CfgTimerTable(table, target, i_port, o_port):
    print("configure forwarding table")
    table.entry_add(
        target,
        [table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', i_port),
                                  gc.KeyTuple('hdr.timer.app_id', 1)])],
        [table.make_data([gc.DataTuple('port', o_port)],
                                  'SwitchIngress.match')]
    )

def CfgSetDataTable(table, target):
    print("configure egress table")
    table.entry_add(
        target,
        [table.make_key([gc.KeyTuple('hdr.timer.app_id', 1)])],
        [table.make_data('SwitchEgress.match')]
    )

if bfrt_info.p4_name!='IBLT_IN':
    print("error")
else:
    print("connect")
    pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
    pktgen_pkt_buffer_table = bfrt_info.table_get("pkt_buffer")
    pktgen_port_cfg_table = bfrt_info.table_get("port_cfg")
    i_t_table = bfrt_info.table_get("SwitchIngress.t")
    target =gc.Target(device_id=0,pipe_id=0xffff)
    pktlen = 100
    p = testutils.simple_eth_packet(pktlen=pktlen,eth_src="0f:0f:0f:0f:0f:0f")
    p1=testutils.simple_ipv4ip_packet(pktlen=pktlen,eth_src="0f:0f:0f:0f:0f:0f")
    pgen_pipe_id = 0
    src_port = 68
    buff_offset = 144
    p_count = 4  # packets per batch
    b_count = 1  # batch number
    pkt_lst = []
    # pkt_len = [pktlen] * p_count * b_count
    # for batch in range(b_count):
    #     for pkt_num in range(p_count):
    #         dmac = pgen_timer_hdr_to_dmac(pgen_pipe_id, 0, batch, pkt_num)
    #         p_exp = testutils.simple_eth_packet(pktlen=pktlen, eth_dst=dmac)
    #         pkt_lst.append(p_exp)

    try:
        CfgTimerTable(i_t_table, target, src_port, 64)
        #CfgSetDataTable(e_set_data_table,target)
        pktgen_port_cfg_table.entry_add(
                target,
                [pktgen_port_cfg_table.make_key([gc.KeyTuple('dev_port', src_port)])],
                [pktgen_port_cfg_table.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])])
        resp = pktgen_port_cfg_table.entry_get(
            target,
            [pktgen_port_cfg_table.make_key([gc.KeyTuple('dev_port', src_port)])],
            {"from_hw": False},
            pktgen_port_cfg_table.make_data([gc.DataTuple("pktgen_enable")], get=True))
        data_dict = next(resp)[0].to_dict()
        data = pktgen_app_cfg_table.make_data([gc.DataTuple('timer_nanosec', 2000000000),
                                                       gc.DataTuple('app_enable', bool_val=False),
                                                       gc.DataTuple('pkt_len', (pktlen)),
                                                       gc.DataTuple('pkt_buffer_offset', buff_offset),
                                                       gc.DataTuple('pipe_local_source_port', src_port),
                                                       gc.DataTuple('increment_source_port', bool_val=False),
                                                       gc.DataTuple('batch_count_cfg', b_count - 1),
                                                       gc.DataTuple('packets_per_batch_cfg', p_count - 1),
                                                       gc.DataTuple('ibg', 1),
                                                       gc.DataTuple('ibg_jitter', 0),
                                                       gc.DataTuple('ipg', 1000),
                                                       gc.DataTuple('ipg_jitter', 500),
                                                       gc.DataTuple('batch_counter', 0),
                                                       gc.DataTuple('pkt_counter', 0),
                                                       gc.DataTuple('trigger_counter', 0)],
                                                      'trigger_timer_periodic')
        pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', 1)])],
                [data])
        resp = pktgen_app_cfg_table.entry_get(
            target,
            [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', 1)])]
        )
        data_dict = next(resp)[0].to_dict()
        pktgen_pkt_buffer_table.entry_add(
                target,
                [pktgen_pkt_buffer_table.make_key([gc.KeyTuple('pkt_buffer_offset', buff_offset),
                                                   gc.KeyTuple('pkt_buffer_size', pktlen)])],
                [pktgen_pkt_buffer_table.make_data([gc.DataTuple('buffer', bytearray(bytes(p)))])])
        print(data_dict)
        pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', 1)])],
                [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=True)],
                                                'trigger_timer_periodic')]
            )
    except gc.BfruntimeRpcException as e:
        raise e
    finally:
        pass