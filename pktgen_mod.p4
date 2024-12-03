/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#include <tna.p4>

header telemetry_h {
    bit<8> protocol;            //layer4 proto
    bit<8> IBLT_bitmap;         //提示控制器镜像包含有哪个IBLT内容，1中，2高，3中+高
    bit<16> medium_index;       //IBLT哪一列
    bit<16> high_index;
    //中IBLT, row0 + row1
    bit<32> srcIP_0_0;
    bit<32> dstIP_0_0;
    bit<32> ports_0_0;
    bit<8> proto_0_0;
    bit<8> fCnt_0_0;
    bit<16> pCnt_0_0;

    bit<32> srcIP_0_1;
    bit<32> dstIP_0_1;
    bit<32> ports_0_1;
    bit<8> proto_0_1;
    bit<8> fCnt_0_1;
    bit<16> pCnt_0_1;
    
    //高IBLT, row0 + row1
    bit<32> srcIP_1_0;
    bit<32> dstIP_1_0;
    bit<32> ports_1_0;
    bit<8> proto_1_0;
    bit<8> fCnt_1_0;
    bit<16> pCnt_1_0;

    bit<32> srcIP_1_1;
    bit<32> dstIP_1_1;
    bit<32> ports_1_1;
    bit<8> proto_1_1;
    bit<8> fCnt_1_1;
    bit<16> pCnt_1_1;
}


struct headers {
    pktgen_timer_header_t timer;
    telemetry_h telemetry;
}

parser PktIngressParser(
       packet_in packet, 
       out headers hdr, 
       out empty_metadata_t md,
       out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);

        pktgen_timer_header_t pktgen_pd_hdr = packet.lookahead<pktgen_timer_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            default : accept;
        }
    }

    state parse_pktgen_timer {
        packet.extract(hdr.timer);
        transition accept;
    }

}


control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in empty_metadata_t md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}


control SwitchIngress(
        inout headers hdr, 
        inout empty_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action match(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    table t {
        key = {
            hdr.timer.app_id  : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            match;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    apply {
        if (hdr.timer.isValid()) {
            t.apply();
        } else {
            drop();
        }
        // No need for egress processing, skip it and use empty controls for egress.
    }
}

parser SwitchEgressParser(
       packet_in packet, 
       out headers hdr, 
       out empty_metadata_t md,
       out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        pktgen_timer_header_t pktgen_pd_hdr = packet.lookahead<pktgen_timer_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            default : accept;
        }
    }

    state parse_pktgen_timer {
        packet.extract(hdr.timer);
        packet.extract(hdr.telemetry);
        transition accept;
    }

}


control SwitchEgressDeparser(
        packet_out pkt,
        inout headers hdr,
        in empty_metadata_t md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchEgress(
        inout headers hdr,
        inout empty_metadata_t md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_intr_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
        
    action nop() {
    }

    action match() {
        hdr.telemetry.protocol=6;
        hdr.telemetry.IBLT_bitmap=3;
        hdr.telemetry.medium_index=16;
        hdr.telemetry.high_index=17;
    }

    table set_data {
        key = {
            hdr.timer.app_id  : exact;
        }
        actions = {
            match;
            @defaultonly nop;
        }
        const default_action = nop();
        size = 1024;
        const entries ={
            (1) : match();
        }
    }
    apply {
        if (hdr.timer.isValid()) {
            set_data.apply();
        } else {
            nop();
        }
        // No need for egress processing, skip it and use empty controls for egress.
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
