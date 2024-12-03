/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
const ip_protocol_t IP_PROTOCOLS_TELEMETRY = 250;

typedef bit<8> pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

typedef bit<10> hash_index_width_t;
typedef bit<1> BF_element_width_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    // ...
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

//编译时提示，header结构内不能嵌套定义header
//metadata的struct可以
//70Bytes
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

//ingress桥接头，需要字节对齐
header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    bit<8> is_5tup_pkt;       //只有5元组的包此flag为1
    @padding bit<6> _pad1;
    hash_index_width_t hash_row0_index;
    @padding bit<6> _pad2;
    hash_index_width_t hash_row1_index;

    //端口桥接过去给egress用
    bit<16> layer4_src_port;
    bit<16> layer4_dst_port;
    //32位方便register操作,src高位,dst低位
    bit<32> layer4_srcdst_ports;

}

//镜像包的镜像头，首个字段需与bridge header的首个字段，egress parser使用此字段判断包类型
//最长32bytes
//1Byte
header mirror_h {
    pkt_type_t  pkt_type;
}

struct ig_metadata_t {
    bit<8> routed;
}

/*
struct pair_32 {
    bit<32>    first;
    bit<32>    second;
}

struct pair_16 {
    bit<16>    first;
    bit<16>    second;
}
*/

struct eg_metadata_t {
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
    mirror_h mirror_header;   //egress parser解析镜像包时，将镜像头存入metadata

    hash_index_width_t hash_row0_index;
    hash_index_width_t hash_row1_index;

    //0:无拥塞，1:中拥塞，2:高拥塞
    bit<8> congest_type;
    //中,高IBLT的50ms epoch flag
    bit<1> epoch_end_flag;
    
    //中,高IBLT遍历index,遍历时再取最低10位
    bit<20> rdclIBLT_index;
    //最终实际中高IBLT表所用index，在hash和reg中选择
    hash_index_width_t high_row0_index;
    hash_index_width_t high_row1_index;
    hash_index_width_t medium_row0_index;
    hash_index_width_t medium_row1_index;

    //中IBLT操作符
    //0:不操作，1:插入，2:读取并清空
    bit<2> mediumIBLT_op;
    //高IBLT操作符
    //0:不操作，1:插入，2:读取并清空
    bit<2> highIBLT_op;

    BF_element_width_t BF_row0_val;
    BF_element_width_t BF_row1_val;
    BF_element_width_t BF_query_val;
}

struct headers_t {
    mirror_bridged_metadata_h bridged_md;
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ///ipv6_h ipv6;
    pktgen_timer_header_t timer;
    telemetry_h telemetry;
    tcp_h tcp;
    udp_h udp;
    // Add more headers here.
}

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser Layer4Parser(
    packet_in pkt,
    out headers_t hdr) {
    state start {
        pktgen_timer_header_t pktgen_pd_hdr = pkt.lookahead<pktgen_timer_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            default : parse_ethernet;
        }
    }

    state parse_pktgen_timer {
        pkt.extract(hdr.timer);
        pkt.advance(64);
        transition parse_ipv4;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default : accept;
        }
    }
    state parse_vlan {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TELEMETRY : parse_telemetry;
            default : accept;
        }
    }

    state parse_telemetry{
        pkt.extract(hdr.telemetry);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    Layer4Parser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        layer4_parser.apply(pkt, hdr);
    }
    
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Switch Ingress MAU
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout headers_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action route_to_port(PortId_t dest_port) {
        ig_dprsr_md.drop_ctl = 0x0;
        ig_tm_md.ucast_egress_port = dest_port;
        ig_md.routed = 1;

    }

    action drop() {
        // Mark packet for dropping after ingress.
        ig_md.routed = 0;
        ig_dprsr_md.drop_ctl = 0x1;
        
    }

    //L2 FIB
    table L2_fwd {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            route_to_port;
            drop;
        }

        size = 512;
        default_action = drop();
    }

    //port-to-port forward
    table p2p_fwd {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            route_to_port;
            drop;
        }

        size = 512;
        default_action = drop();
    }

    Hash<hash_index_width_t>(HashAlgorithm_t.CRC32) hash_5tup_row0_tcp;
    Hash<hash_index_width_t>(HashAlgorithm_t.CRC32) hash_5tup_row0_udp;
    Hash<hash_index_width_t>(HashAlgorithm_t.CRC16) hash_5tup_row1_tcp;
    Hash<hash_index_width_t>(HashAlgorithm_t.CRC16) hash_5tup_row1_udp;

    action calc_hash_index_5tup_tcp() {
        hdr.bridged_md.hash_row0_index = hash_5tup_row0_tcp.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            hdr.ipv4.protocol
        });
        hdr.bridged_md.hash_row1_index = hash_5tup_row1_tcp.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            hdr.ipv4.protocol
        });
        hdr.bridged_md.is_5tup_pkt = 8w1;
        hdr.bridged_md.layer4_src_port = hdr.tcp.src_port;
        hdr.bridged_md.layer4_dst_port = hdr.tcp.dst_port;
    }

    action calc_hash_index_5tup_udp() {
        hdr.bridged_md.hash_row0_index = hash_5tup_row0_udp.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.udp.src_port,
            hdr.udp.dst_port,
            hdr.ipv4.protocol
        });
        hdr.bridged_md.hash_row1_index = hash_5tup_row1_udp.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.udp.src_port,
            hdr.udp.dst_port,
            hdr.ipv4.protocol
        });
        hdr.bridged_md.is_5tup_pkt = 8w1;
        hdr.bridged_md.layer4_src_port = hdr.udp.src_port;
        hdr.bridged_md.layer4_dst_port = hdr.udp.dst_port;
    }

    action set_normal_pkt() {
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
    }

    action set_srcdst_ports() {
        hdr.bridged_md.layer4_srcdst_ports = hdr.bridged_md.layer4_src_port ++ hdr.bridged_md.layer4_dst_port;
    }

    action copy2cpu_test() {
        ig_tm_md.copy_to_cpu = 1;
        ig_tm_md.icos_for_copy_to_cpu = 0;
    }

    action match(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_dprsr_md.drop_ctl = 0x0;
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
        if(hdr.timer.isValid()){
            t.apply();
        }
        //每个包计算hash后的index
        else{
            set_normal_pkt();
            if (hdr.ipv4.protocol == IP_PROTOCOLS_TCP) {
			calc_hash_index_5tup_tcp();
		    }
		    else if (hdr.ipv4.protocol == IP_PROTOCOLS_UDP) {
			    calc_hash_index_5tup_udp();
		    }

            set_srcdst_ports();
            L2_fwd.apply();
            if (ig_md.routed != 1) {
                p2p_fwd.apply();
        }
        }
        //会直接copy一份到CPU端口
        //copy2cpu_test();
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out headers_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;
    //PktParser() pkt_parser;
    Layer4Parser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        //pkt_parser.apply(pkt,hdr);
        pktgen_timer_header_t pktgen_pd_hdr = pkt.lookahead<pktgen_timer_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            default : parse_bridged_md;
        }
    }

    state parse_bridged_md {
        eg_md.mirror_header.pkt_type = PKT_TYPE_NORMAL;
        pkt.extract(hdr.bridged_md);
        eg_md.hash_row0_index = hdr.bridged_md.hash_row0_index;
        eg_md.hash_row1_index = hdr.bridged_md.hash_row1_index;
        //eg_md.layer4_srcdst_ports = hdr.bridged_md.layer4_srcdst_ports;
        
        transition accept;
    }

    state parse_pktgen_timer {
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.timer);
        pkt.emit(hdr.telemetry);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// ---------------------------------------------------------------------------
// Switch Egress MAU
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout headers_t hdr,
        inout eg_metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    

    action nop() {
    }
    
    action set_congest_type(bit<8> type) {
        eg_md.congest_type = type;
    }

    //确定拥塞类型
    //key: deq_qdepth范围匹配
    //val: eg_md.mirror_header.congest_type
    //0:低拥塞，1:中拥塞，2:高拥塞
    table tb_congest_decide {
        key = {
            eg_intr_md.deq_qdepth : range;
            //调试用
            //hdr.udp.src_port : range;
        }

        actions = {
            set_congest_type;
            nop;
        }

        default_action = nop();
        /*
        const entries = {
            0..1200 : set_congest_type(0);
            1200..4800 : set_congest_type(1);
            4800..50000 : set_congest_type(2);
        }
        */
    }

    //10ms epoch flag，每个包都判断，50ms结束时更新一次tstamp

    //遍历中IBLT的index，epoch_end_flag = 1时初始化为0，每个无拥塞包读取index并+1
    // Register<bit<32>, _>(1, 0) rdclIBLT_index_reg;
    // RegisterAction<bit<32>, _, bit<32>>(rdclIBLT_index_reg) rdclIBLT_index_update_action = {
    //     void apply(inout bit<32> val, out bit<32> rv) {
    //         if (eg_md.epoch_end_flag == 1) {
    //             val = 0;
    //         }
    //         if (eg_md.congest_type == 0) {
    //             rv = val;
    //             val = val + 1;
    //         }
    //     }
    // };

    // action rdclIBLT_index_update() {
    //     eg_md.rdclIBLT_index = (bit<20>)rdclIBLT_index_update_action.execute(0);
    // }

    action IBLT_nop() {
        eg_md.mediumIBLT_op = 0;
        eg_md.highIBLT_op = 0;
    }

    action highIBLT_insert() {
        eg_md.mediumIBLT_op = 0;
        eg_md.highIBLT_op = 1;
        eg_md.high_row0_index = eg_md.hash_row0_index;
        eg_md.high_row1_index = eg_md.hash_row1_index;
    }

    action mediumIBLT_insert() {
        eg_md.mediumIBLT_op = 1;
        eg_md.highIBLT_op = 0;
        eg_md.medium_row0_index = eg_md.hash_row0_index;
        eg_md.medium_row1_index = eg_md.hash_row1_index;
    }

    /*
    action mediumIBLT_rd_and_cl() {
        eg_md.mediumIBLT_op = 2;
        eg_md.highIBLT_op = 0;
        eg_md.medium_row0_index = (bit<10>)eg_md.mediumIBLT_index;
        eg_md.medium_row1_index = (bit<10>)eg_md.mediumIBLT_index;
        hdr.bridged_md.is_5tup_pkt = 1;

        hdr.telemetry.setValid();
        hdr.telemetry.protocol = hdr.ipv4.protocol;
        hdr.ipv4.protocol = IP_PROTOCOLS_TELEMETRY;
        hdr.ipv4.total_len = hdr.ipv4.total_len + 70;
        hdr.telemetry.IBLT_bitmap = 1;
        hdr.telemetry.medium_index = (bit<16>)eg_md.medium_row0_index;
    }

    action highIBLT_rd_and_cl() {
        eg_md.mediumIBLT_op = 0;
        eg_md.highIBLT_op = 2;
        eg_md.high_row0_index = (bit<10>)eg_md.highIBLT_index;
        eg_md.high_row1_index = (bit<10>)eg_md.highIBLT_index;
        hdr.bridged_md.is_5tup_pkt = 1;

        hdr.telemetry.setValid();
        hdr.telemetry.protocol = hdr.ipv4.protocol;
        hdr.ipv4.protocol = IP_PROTOCOLS_TELEMETRY;
        hdr.ipv4.total_len = hdr.ipv4.total_len + 70;
        hdr.telemetry.IBLT_bitmap = 2;
        hdr.telemetry.high_index = (bit<16>)eg_md.high_row0_index;
    }
    */

    action all_rd_and_cl() {
        eg_md.mediumIBLT_op = 2;
        eg_md.highIBLT_op = 2;
        eg_md.medium_row0_index = (bit<10>)hdr.timer.packet_id;
        eg_md.medium_row1_index = (bit<10>)hdr.timer.packet_id;
        eg_md.high_row0_index = (bit<10>)hdr.timer.packet_id;
        eg_md.high_row1_index = (bit<10>)hdr.timer.packet_id;
        hdr.bridged_md.is_5tup_pkt = (bit<8>)1;
    }

    action set_data(){
        hdr.telemetry.protocol = (bit<8>)250;
        hdr.telemetry.IBLT_bitmap = (bit<8>)3;
        hdr.telemetry.medium_index = (bit<16>)eg_md.medium_row0_index;
        hdr.telemetry.high_index = (bit<16>)eg_md.high_row0_index;
    }
    //操作表，决定中，高IBLT插入还是遍历
    // error: : Currently in p4c, 
    // the table tb_operation_decide_0 cannot perform a range match on key 
    // egress::eg_md.mediumIBLT_index as the key does not fit in under 5 PHV nibbles
    // 范围匹配的key要在5 * 4  = 20bits以内
    
    table tb_operation_decide {
        key = {
            eg_md.congest_type : exact;
        }

        actions = {
            highIBLT_insert;
            mediumIBLT_insert;
            all_rd_and_cl;
            IBLT_nop;
        }

        default_action = IBLT_nop();
        
        
        const entries = {
            //无拥塞包，根据index范围遍历相应IBLT
            (0) : all_rd_and_cl();
            //中拥塞包，一律插入中IBLT
            (1) : mediumIBLT_insert();
            //高拥塞包，一律插入高IBLT
            (2) : highIBLT_insert();
        }
        
    }
    

    /*
    action medium_test() {
        eg_md.mediumIBLT_op = 2;
        eg_md.highIBLT_op = 0;
        eg_md.medium_row0_index = (bit<10>)hdr.telemetry.medium_index;
        eg_md.medium_row1_index = (bit<10>)hdr.telemetry.medium_index;
        hdr.bridged_md.is_5tup_pkt = 1;
    }

    action high_test() {
        eg_md.mediumIBLT_op = 0;
        eg_md.highIBLT_op = 2;
        eg_md.high_row0_index = (bit<10>)hdr.telemetry.high_index;
        eg_md.high_row1_index = (bit<10>)hdr.telemetry.high_index;
        hdr.bridged_md.is_5tup_pkt = 1;
    }

    action all_test() {
        eg_md.mediumIBLT_op = 2;
        eg_md.highIBLT_op = 2;
        eg_md.medium_row0_index = (bit<10>)hdr.telemetry.medium_index;
        eg_md.medium_row1_index = (bit<10>)hdr.telemetry.medium_index;
        eg_md.high_row0_index = (bit<10>)hdr.telemetry.high_index;
        eg_md.high_row1_index = (bit<10>)hdr.telemetry.high_index;
        hdr.bridged_md.is_5tup_pkt = 1;
    }

    //直接发包提取IBLT测试
    table tb_rd_and_cl_test {
        key = {
            hdr.telemetry.IBLT_bitmap : exact;
        }

        actions = {
            medium_test;
            high_test;
            all_test;
            IBLT_nop;
        }

        default_action = IBLT_nop();

        const entries = {
            2 : high_test();
            1 : medium_test();
            3 : all_test();
        }
    }
    */

    // BF 1024cols 2rows, 98.25% flowID recall
    //const bit<32> BF_register_size = 1 << 10;
    Register<BF_element_width_t, _>(1024, 0) BF_0_row0;
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row0) BF_0_row0_query_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row0) BF_0_row0_readonly_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
        }
    };

    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row0) BF_0_row0_clear_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            val = 0;
            rv = val;
        }
    };


    Register<BF_element_width_t, _>(1024, 0) BF_0_row1;
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row1) BF_0_row1_query_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row1) BF_0_row1_readonly_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_0_row1) BF_0_row1_clear_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            val = 0;
            rv = val;
        }
    };


    Register<BF_element_width_t, _>(1024, 0) BF_1_row0;
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row0) BF_1_row0_query_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row0) BF_1_row0_readonly_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row0) BF_1_row0_clear_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            val = 0;
            rv = val;
        }
    };

    Register<BF_element_width_t, _>(1024, 0) BF_1_row1;
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row1) BF_1_row1_query_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row1) BF_1_row1_readonly_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            rv = val;
        }
    };
    RegisterAction<BF_element_width_t, _, BF_element_width_t>(BF_1_row1) BF_1_row1_clear_action = {
        void apply(inout BF_element_width_t val, out BF_element_width_t rv) {
            val = 0;
            rv = val;
        }
    };

    action BF_0_query_row0() {
        eg_md.BF_row0_val = BF_0_row0_query_action.execute(eg_md.medium_row0_index);
    }

    action BF_0_read_row0() {
        BF_0_row0_readonly_action.execute(eg_md.medium_row0_index);
    }
	
	action BF_0_clear_row0() {
        BF_0_row0_clear_action.execute(eg_md.medium_row0_index);
    }

    action BF_0_query_row1() {
        eg_md.BF_row1_val = BF_0_row1_query_action.execute(eg_md.medium_row1_index);
        eg_md.BF_query_val = eg_md.BF_row0_val & eg_md.BF_row1_val;
    }

    action BF_0_read_row1() {
        BF_0_row1_readonly_action.execute(eg_md.medium_row1_index);
    }
	
	action BF_0_clear_row1() {
        BF_0_row1_clear_action.execute(eg_md.medium_row1_index);
    }

    action BF_1_query_row0() {
        eg_md.BF_row0_val = BF_1_row0_query_action.execute(eg_md.high_row0_index);
    }

    action BF_1_read_row0() {
        BF_1_row0_readonly_action.execute(eg_md.high_row0_index);
    }
	
	action BF_1_clear_row0() {
        BF_1_row0_clear_action.execute(eg_md.high_row0_index);
    }

    action BF_1_query_row1() {
        eg_md.BF_row1_val = BF_1_row1_query_action.execute(eg_md.high_row1_index);
        eg_md.BF_query_val = eg_md.BF_row0_val & eg_md.BF_row1_val;
    }

    action BF_1_read_row1() {
        BF_1_row1_readonly_action.execute(eg_md.high_row1_index);
    }
	
	action BF_1_clear_row1() {
        BF_1_row1_clear_action.execute(eg_md.high_row1_index);
    }


    table tb_BF_0_query_row0 {
        key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            BF_0_query_row0();
            BF_0_read_row0();
			BF_0_clear_row0();
        }

        size = 3;

        const entries = {
            0 : BF_0_read_row0();
            1 : BF_0_query_row0();
			2 : BF_0_clear_row0();
        }
    }

    table tb_BF_0_query_row1 {
        key = {
            eg_md.mediumIBLT_op : exact;
        }

        size = 3;

        actions = {
            BF_0_query_row1();
            BF_0_read_row1();
			BF_0_clear_row1();
        }

        const entries = {
            0 : BF_0_read_row1();
            1 : BF_0_query_row1();
			2 : BF_0_clear_row1();
        }
    }
    
    table tb_BF_1_query_row0 {
        key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            BF_1_query_row0();
            BF_1_read_row0();
			BF_1_clear_row0();
        }

        size = 3;

        const entries = {
            0 : BF_1_read_row0();
            1 : BF_1_query_row0();
			2 : BF_1_clear_row0();
        }
    }

    table tb_BF_1_query_row1 {
        key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            BF_1_query_row1();
            BF_1_read_row1();
			BF_1_clear_row1();
        }

        size = 3;

        const entries = {
            0 : BF_1_read_row1();
            1 : BF_1_query_row1();
			2 : BF_1_clear_row1();
        }
    }
    

    //中IBLT srcIP部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_0_srcIP_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row0) IBLT_0_srcIP_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.src_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row0) IBLT_0_srcIP_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row0) IBLT_0_srcIP_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
			rv = val;
            val = 0;
        }
    };

    //中IBLT dstIP部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_0_dstIP_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row0) IBLT_0_dstIP_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.dst_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row0) IBLT_0_dstIP_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row0) IBLT_0_dstIP_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT 端口部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_0_ports_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row0) IBLT_0_ports_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.bridged_md.layer4_srcdst_ports;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row0) IBLT_0_ports_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row0) IBLT_0_ports_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT pktCount部分 row0
    Register<bit<16>, _>(1024, 0) IBLT_0_pktCnt_row0;
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row0) IBLT_0_pktCnt_row0_insert_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            val = val + 1;
            rv = 0;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row0) IBLT_0_pktCnt_row0_nop_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row0) IBLT_0_pktCnt_row0_rd_and_cl_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT proto部分 row0
    Register<bit<8>, _>(1024, 0) IBLT_0_proto_row0;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row0) IBLT_0_proto_row0_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.protocol;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row0) IBLT_0_proto_row0_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row0) IBLT_0_proto_row0_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT flowCount部分 row0
    Register<bit<8>, _>(1024, 0) IBLT_0_flowCnt_row0;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row0) IBLT_0_flowCnt_row0_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val + 1;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row0) IBLT_0_flowCnt_row0_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row0) IBLT_0_flowCnt_row0_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };


    action IBLT_0_srcIP_row0_update() {
        IBLT_0_srcIP_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_srcIP_row0_nop() {
        IBLT_0_srcIP_row0_nop_action.execute(eg_md.medium_row0_index);
    }
		action IBLT_0_srcIP_row0_rd_and_cl() {
        hdr.telemetry.srcIP_0_0 = IBLT_0_srcIP_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }

    action IBLT_0_dstIP_row0_update() {
        IBLT_0_dstIP_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_dstIP_row0_nop() {
        IBLT_0_dstIP_row0_nop_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_dstIP_row0_rd_and_cl() {
        hdr.telemetry.dstIP_0_0 = IBLT_0_dstIP_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }

    action IBLT_0_ports_row0_update() {
        IBLT_0_ports_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_ports_row0_nop() {
        IBLT_0_ports_row0_nop_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_ports_row0_rd_and_cl() {
        hdr.telemetry.ports_0_0 = IBLT_0_ports_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }

    action IBLT_0_pktCnt_row0_update() {
        IBLT_0_pktCnt_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_pktCnt_row0_nop() {
        IBLT_0_pktCnt_row0_nop_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_pktCnt_row0_rd_and_cl() {
        hdr.telemetry.pCnt_0_0 = IBLT_0_pktCnt_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }

    action IBLT_0_proto_row0_update() {
        IBLT_0_proto_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_proto_row0_nop() {
        IBLT_0_proto_row0_nop_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_proto_row0_rd_and_cl() {
        hdr.telemetry.proto_0_0 = IBLT_0_proto_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }

    action IBLT_0_flowCnt_row0_update() {
        IBLT_0_flowCnt_row0_insert_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_flowCnt_row0_nop() {
        IBLT_0_flowCnt_row0_nop_action.execute(eg_md.medium_row0_index);
    }
	action IBLT_0_flowCnt_row0_rd_and_cl() {
        hdr.telemetry.fCnt_0_0 = IBLT_0_flowCnt_row0_rd_and_cl_action.execute(eg_md.medium_row0_index);
    }
	
	table tb_IBLT_0_srcIP_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_srcIP_row0_update();
            IBLT_0_srcIP_row0_nop();
			IBLT_0_srcIP_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_srcIP_row0_nop();
            1 : IBLT_0_srcIP_row0_update();
			2 : IBLT_0_srcIP_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_dstIP_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_dstIP_row0_update();
            IBLT_0_dstIP_row0_nop();
			IBLT_0_dstIP_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_dstIP_row0_nop();
            1 : IBLT_0_dstIP_row0_update();
			2 : IBLT_0_dstIP_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_ports_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_ports_row0_update();
            IBLT_0_ports_row0_nop();
			IBLT_0_ports_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_ports_row0_nop();
            1 : IBLT_0_ports_row0_update();
			2 : IBLT_0_ports_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_pktCnt_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_pktCnt_row0_update();
            IBLT_0_pktCnt_row0_nop();
			IBLT_0_pktCnt_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_pktCnt_row0_nop();
            1 : IBLT_0_pktCnt_row0_update();
			2 : IBLT_0_pktCnt_row0_rd_and_cl();
        }
	}

	table tb_IBLT_0_proto_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_proto_row0_update();
            IBLT_0_proto_row0_nop();
			IBLT_0_proto_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_proto_row0_nop();
            1 : IBLT_0_proto_row0_update();
			2 : IBLT_0_proto_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_flowCnt_row0_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_flowCnt_row0_update();
            IBLT_0_flowCnt_row0_nop();
			IBLT_0_flowCnt_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_flowCnt_row0_nop();
            1 : IBLT_0_flowCnt_row0_update();
			2 : IBLT_0_flowCnt_row0_rd_and_cl();
        }
	}



    //中IBLT srcIP部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_0_srcIP_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row1) IBLT_0_srcIP_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.src_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row1) IBLT_0_srcIP_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_srcIP_row1) IBLT_0_srcIP_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
			rv = val;
            val = 0;
        }
    };

    //中IBLT dstIP部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_0_dstIP_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row1) IBLT_0_dstIP_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.dst_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row1) IBLT_0_dstIP_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_dstIP_row1) IBLT_0_dstIP_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT 端口部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_0_ports_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row1) IBLT_0_ports_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.bridged_md.layer4_srcdst_ports;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row1) IBLT_0_ports_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_0_ports_row1) IBLT_0_ports_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT pktCount部分 row1
    Register<bit<16>, _>(1024, 0) IBLT_0_pktCnt_row1;
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row1) IBLT_0_pktCnt_row1_insert_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            val = val + 1;
            rv = 0;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row1) IBLT_0_pktCnt_row1_nop_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_0_pktCnt_row1) IBLT_0_pktCnt_row1_rd_and_cl_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT proto部分 row1
    Register<bit<8>, _>(1024, 0) IBLT_0_proto_row1;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row1) IBLT_0_proto_row1_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.protocol;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row1) IBLT_0_proto_row1_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_proto_row1) IBLT_0_proto_row1_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };

    //中IBLT flowCount部分 row1
    Register<bit<8>, _>(1024, 0) IBLT_0_flowCnt_row1;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row1) IBLT_0_flowCnt_row1_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val + 1;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row1) IBLT_0_flowCnt_row1_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_0_flowCnt_row1) IBLT_0_flowCnt_row1_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };


    action IBLT_0_srcIP_row1_update() {
        IBLT_0_srcIP_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_srcIP_row1_nop() {
        IBLT_0_srcIP_row1_nop_action.execute(eg_md.medium_row1_index);
    }
		action IBLT_0_srcIP_row1_rd_and_cl() {
        hdr.telemetry.srcIP_0_1 = IBLT_0_srcIP_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }

    action IBLT_0_dstIP_row1_update() {
        IBLT_0_dstIP_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_dstIP_row1_nop() {
        IBLT_0_dstIP_row1_nop_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_dstIP_row1_rd_and_cl() {
        hdr.telemetry.dstIP_0_1 = IBLT_0_dstIP_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }

    action IBLT_0_ports_row1_update() {
        IBLT_0_ports_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_ports_row1_nop() {
        IBLT_0_ports_row1_nop_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_ports_row1_rd_and_cl() {
        hdr.telemetry.ports_0_1 = IBLT_0_ports_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }

    action IBLT_0_pktCnt_row1_update() {
        IBLT_0_pktCnt_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_pktCnt_row1_nop() {
        IBLT_0_pktCnt_row1_nop_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_pktCnt_row1_rd_and_cl() {
        hdr.telemetry.pCnt_0_1 = IBLT_0_pktCnt_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }

    action IBLT_0_proto_row1_update() {
        IBLT_0_proto_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_proto_row1_nop() {
        IBLT_0_proto_row1_nop_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_proto_row1_rd_and_cl() {
        hdr.telemetry.proto_0_1 = IBLT_0_proto_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }

    action IBLT_0_flowCnt_row1_update() {
        IBLT_0_flowCnt_row1_insert_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_flowCnt_row1_nop() {
        IBLT_0_flowCnt_row1_nop_action.execute(eg_md.medium_row1_index);
    }
	action IBLT_0_flowCnt_row1_rd_and_cl() {
        hdr.telemetry.fCnt_0_1 = IBLT_0_flowCnt_row1_rd_and_cl_action.execute(eg_md.medium_row1_index);
    }
	
	table tb_IBLT_0_srcIP_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_srcIP_row1_update();
            IBLT_0_srcIP_row1_nop();
			IBLT_0_srcIP_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_srcIP_row1_nop();
            1 : IBLT_0_srcIP_row1_update();
			2 : IBLT_0_srcIP_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_dstIP_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_dstIP_row1_update();
            IBLT_0_dstIP_row1_nop();
			IBLT_0_dstIP_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_dstIP_row1_nop();
            1 : IBLT_0_dstIP_row1_update();
			2 : IBLT_0_dstIP_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_ports_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_ports_row1_update();
            IBLT_0_ports_row1_nop();
			IBLT_0_ports_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_ports_row1_nop();
            1 : IBLT_0_ports_row1_update();
			2 : IBLT_0_ports_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_pktCnt_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_pktCnt_row1_update();
            IBLT_0_pktCnt_row1_nop();
			IBLT_0_pktCnt_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_pktCnt_row1_nop();
            1 : IBLT_0_pktCnt_row1_update();
			2 : IBLT_0_pktCnt_row1_rd_and_cl();
        }
	}

	table tb_IBLT_0_proto_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_proto_row1_update();
            IBLT_0_proto_row1_nop();
			IBLT_0_proto_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_proto_row1_nop();
            1 : IBLT_0_proto_row1_update();
			2 : IBLT_0_proto_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_0_flowCnt_row1_insert {
		key = {
            eg_md.mediumIBLT_op : exact;
        }

        actions = {
            IBLT_0_flowCnt_row1_update();
            IBLT_0_flowCnt_row1_nop();
			IBLT_0_flowCnt_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_0_flowCnt_row1_nop();
            1 : IBLT_0_flowCnt_row1_update();
			2 : IBLT_0_flowCnt_row1_rd_and_cl();
        }
	}




    //高IBLT srcIP部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_1_srcIP_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row0) IBLT_1_srcIP_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.src_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row0) IBLT_1_srcIP_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row0) IBLT_1_srcIP_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
			rv = val;
            val = 0;
        }
    };

    //高IBLT dstIP部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_1_dstIP_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row0) IBLT_1_dstIP_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.dst_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row0) IBLT_1_dstIP_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row0) IBLT_1_dstIP_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT 端口部分 row0
    Register<bit<32>, _>(1024, 0) IBLT_1_ports_row0;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row0) IBLT_1_ports_row0_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.bridged_md.layer4_srcdst_ports;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row0) IBLT_1_ports_row0_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row0) IBLT_1_ports_row0_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT pktCount部分 row0
    Register<bit<16>, _>(1024, 0) IBLT_1_pktCnt_row0;
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row0) IBLT_1_pktCnt_row0_insert_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            val = val + 1;
            rv = 0;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row0) IBLT_1_pktCnt_row0_nop_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row0) IBLT_1_pktCnt_row0_rd_and_cl_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT proto部分 row0
    Register<bit<8>, _>(1024, 0) IBLT_1_proto_row0;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row0) IBLT_1_proto_row0_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.protocol;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row0) IBLT_1_proto_row0_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row0) IBLT_1_proto_row0_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT flowCount部分 row0
    Register<bit<8>, _>(1024, 0) IBLT_1_flowCnt_row0;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row0) IBLT_1_flowCnt_row0_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val + 1;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row0) IBLT_1_flowCnt_row0_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row0) IBLT_1_flowCnt_row0_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };


    action IBLT_1_srcIP_row0_update() {
        IBLT_1_srcIP_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_srcIP_row0_nop() {
        IBLT_1_srcIP_row0_nop_action.execute(eg_md.high_row0_index);
    }
		action IBLT_1_srcIP_row0_rd_and_cl() {
        hdr.telemetry.srcIP_1_0 = IBLT_1_srcIP_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }

    action IBLT_1_dstIP_row0_update() {
        IBLT_1_dstIP_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_dstIP_row0_nop() {
        IBLT_1_dstIP_row0_nop_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_dstIP_row0_rd_and_cl() {
        hdr.telemetry.dstIP_1_0 = IBLT_1_dstIP_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }

    action IBLT_1_ports_row0_update() {
        IBLT_1_ports_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_ports_row0_nop() {
        IBLT_1_ports_row0_nop_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_ports_row0_rd_and_cl() {
        hdr.telemetry.ports_1_0 = IBLT_1_ports_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }

    action IBLT_1_pktCnt_row0_update() {
        IBLT_1_pktCnt_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_pktCnt_row0_nop() {
        IBLT_1_pktCnt_row0_nop_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_pktCnt_row0_rd_and_cl() {
        hdr.telemetry.pCnt_1_0 = IBLT_1_pktCnt_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }

    action IBLT_1_proto_row0_update() {
        IBLT_1_proto_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_proto_row0_nop() {
        IBLT_1_proto_row0_nop_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_proto_row0_rd_and_cl() {
        hdr.telemetry.proto_1_0 = IBLT_1_proto_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }

    action IBLT_1_flowCnt_row0_update() {
        IBLT_1_flowCnt_row0_insert_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_flowCnt_row0_nop() {
        IBLT_1_flowCnt_row0_nop_action.execute(eg_md.high_row0_index);
    }
	action IBLT_1_flowCnt_row0_rd_and_cl() {
        hdr.telemetry.fCnt_1_0 = IBLT_1_flowCnt_row0_rd_and_cl_action.execute(eg_md.high_row0_index);
    }
	
	table tb_IBLT_1_srcIP_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_srcIP_row0_update();
            IBLT_1_srcIP_row0_nop();
			IBLT_1_srcIP_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_srcIP_row0_nop();
            1 : IBLT_1_srcIP_row0_update();
			2 : IBLT_1_srcIP_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_dstIP_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_dstIP_row0_update();
            IBLT_1_dstIP_row0_nop();
			IBLT_1_dstIP_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_dstIP_row0_nop();
            1 : IBLT_1_dstIP_row0_update();
			2 : IBLT_1_dstIP_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_ports_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_ports_row0_update();
            IBLT_1_ports_row0_nop();
			IBLT_1_ports_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_ports_row0_nop();
            1 : IBLT_1_ports_row0_update();
			2 : IBLT_1_ports_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_pktCnt_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_pktCnt_row0_update();
            IBLT_1_pktCnt_row0_nop();
			IBLT_1_pktCnt_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_pktCnt_row0_nop();
            1 : IBLT_1_pktCnt_row0_update();
			2 : IBLT_1_pktCnt_row0_rd_and_cl();
        }
	}

	table tb_IBLT_1_proto_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_proto_row0_update();
            IBLT_1_proto_row0_nop();
			IBLT_1_proto_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_proto_row0_nop();
            1 : IBLT_1_proto_row0_update();
			2 : IBLT_1_proto_row0_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_flowCnt_row0_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_flowCnt_row0_update();
            IBLT_1_flowCnt_row0_nop();
			IBLT_1_flowCnt_row0_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_flowCnt_row0_nop();
            1 : IBLT_1_flowCnt_row0_update();
			2 : IBLT_1_flowCnt_row0_rd_and_cl();
        }
	}



    //高IBLT srcIP部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_1_srcIP_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row1) IBLT_1_srcIP_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.src_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row1) IBLT_1_srcIP_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_srcIP_row1) IBLT_1_srcIP_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
			rv = val;
            val = 0;
        }
    };

    //高IBLT dstIP部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_1_dstIP_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row1) IBLT_1_dstIP_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.dst_addr;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row1) IBLT_1_dstIP_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_dstIP_row1) IBLT_1_dstIP_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT 端口部分 row1
    Register<bit<32>, _>(1024, 0) IBLT_1_ports_row1;
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row1) IBLT_1_ports_row1_insert_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.bridged_md.layer4_srcdst_ports;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row1) IBLT_1_ports_row1_nop_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(IBLT_1_ports_row1) IBLT_1_ports_row1_rd_and_cl_action = {
        void apply(inout bit<32> val, out bit<32> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT pktCount部分 row1
    Register<bit<16>, _>(1024, 0) IBLT_1_pktCnt_row1;
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row1) IBLT_1_pktCnt_row1_insert_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            val = val + 1;
            rv = 0;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row1) IBLT_1_pktCnt_row1_nop_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(IBLT_1_pktCnt_row1) IBLT_1_pktCnt_row1_rd_and_cl_action = {
        void apply(inout bit<16> val, out bit<16> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT proto部分 row1
    Register<bit<8>, _>(1024, 0) IBLT_1_proto_row1;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row1) IBLT_1_proto_row1_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val ^ hdr.ipv4.protocol;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row1) IBLT_1_proto_row1_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_proto_row1) IBLT_1_proto_row1_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };

    //高IBLT flowCount部分 row1
    Register<bit<8>, _>(1024, 0) IBLT_1_flowCnt_row1;
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row1) IBLT_1_flowCnt_row1_insert_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            if (eg_md.BF_query_val == 0) {
                val = val + 1;
            }
            rv = 0;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row1) IBLT_1_flowCnt_row1_nop_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(IBLT_1_flowCnt_row1) IBLT_1_flowCnt_row1_rd_and_cl_action = {
        void apply(inout bit<8> val, out bit<8> rv){
            rv = val;
            val = 0;
        }
    };


    action IBLT_1_srcIP_row1_update() {
        IBLT_1_srcIP_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_srcIP_row1_nop() {
        IBLT_1_srcIP_row1_nop_action.execute(eg_md.high_row1_index);
    }
		action IBLT_1_srcIP_row1_rd_and_cl() {
        hdr.telemetry.srcIP_1_1 = IBLT_1_srcIP_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }

    action IBLT_1_dstIP_row1_update() {
        IBLT_1_dstIP_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_dstIP_row1_nop() {
        IBLT_1_dstIP_row1_nop_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_dstIP_row1_rd_and_cl() {
        hdr.telemetry.dstIP_1_1 = IBLT_1_dstIP_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }

    action IBLT_1_ports_row1_update() {
        IBLT_1_ports_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_ports_row1_nop() {
        IBLT_1_ports_row1_nop_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_ports_row1_rd_and_cl() {
        hdr.telemetry.ports_1_1 = IBLT_1_ports_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }

    action IBLT_1_pktCnt_row1_update() {
        IBLT_1_pktCnt_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_pktCnt_row1_nop() {
        IBLT_1_pktCnt_row1_nop_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_pktCnt_row1_rd_and_cl() {
        hdr.telemetry.pCnt_1_1 = IBLT_1_pktCnt_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }

    action IBLT_1_proto_row1_update() {
        IBLT_1_proto_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_proto_row1_nop() {
        IBLT_1_proto_row1_nop_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_proto_row1_rd_and_cl() {
        hdr.telemetry.proto_1_1 = IBLT_1_proto_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }

    action IBLT_1_flowCnt_row1_update() {
        IBLT_1_flowCnt_row1_insert_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_flowCnt_row1_nop() {
        IBLT_1_flowCnt_row1_nop_action.execute(eg_md.high_row1_index);
    }
	action IBLT_1_flowCnt_row1_rd_and_cl() {
        hdr.telemetry.fCnt_1_1 = IBLT_1_flowCnt_row1_rd_and_cl_action.execute(eg_md.high_row1_index);
    }
	
	table tb_IBLT_1_srcIP_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_srcIP_row1_update();
            IBLT_1_srcIP_row1_nop();
			IBLT_1_srcIP_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_srcIP_row1_nop();
            1 : IBLT_1_srcIP_row1_update();
			2 : IBLT_1_srcIP_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_dstIP_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_dstIP_row1_update();
            IBLT_1_dstIP_row1_nop();
			IBLT_1_dstIP_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_dstIP_row1_nop();
            1 : IBLT_1_dstIP_row1_update();
			2 : IBLT_1_dstIP_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_ports_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_ports_row1_update();
            IBLT_1_ports_row1_nop();
			IBLT_1_ports_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_ports_row1_nop();
            1 : IBLT_1_ports_row1_update();
			2 : IBLT_1_ports_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_pktCnt_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_pktCnt_row1_update();
            IBLT_1_pktCnt_row1_nop();
			IBLT_1_pktCnt_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_pktCnt_row1_nop();
            1 : IBLT_1_pktCnt_row1_update();
			2 : IBLT_1_pktCnt_row1_rd_and_cl();
        }
	}

	table tb_IBLT_1_proto_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_proto_row1_update();
            IBLT_1_proto_row1_nop();
			IBLT_1_proto_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_proto_row1_nop();
            1 : IBLT_1_proto_row1_update();
			2 : IBLT_1_proto_row1_rd_and_cl();
        }
	}
	
	table tb_IBLT_1_flowCnt_row1_insert {
		key = {
            eg_md.highIBLT_op : exact;
        }

        actions = {
            IBLT_1_flowCnt_row1_update();
            IBLT_1_flowCnt_row1_nop();
			IBLT_1_flowCnt_row1_rd_and_cl();
        }

        size = 3;

        const entries = {
            0 : IBLT_1_flowCnt_row1_nop();
            1 : IBLT_1_flowCnt_row1_update();
			2 : IBLT_1_flowCnt_row1_rd_and_cl();
        }
	}

    apply {
            //分类低中高三种拥塞
            //0:低拥塞，1:中拥塞，2:高拥塞
            tb_congest_decide.apply();

            //确定中,高IBLT遍历index
            //rdclIBLT_index_update();

            //操作表，决定中，高IBLT插入还是遍历
            tb_operation_decide.apply();
            if (hdr.timer.isValid() && eg_md.mediumIBLT_op == 2 && eg_md.highIBLT_op == 2){
                set_data();
            }
            else if(eg_md.mediumIBLT_op == 2 && eg_md.highIBLT_op == 2)
            {
                eg_md.mediumIBLT_op = 0;
                eg_md.highIBLT_op = 0;
            }
            if (hdr.bridged_md.is_5tup_pkt == 1) {
                //查询BF,中拥塞BF0，高拥塞BF1
                tb_BF_0_query_row0.apply();
                tb_BF_0_query_row1.apply();

                tb_BF_1_query_row0.apply();
                tb_BF_1_query_row1.apply();

                tb_IBLT_0_srcIP_row0_insert.apply();
				tb_IBLT_0_dstIP_row0_insert.apply();
				tb_IBLT_0_ports_row0_insert.apply();
				tb_IBLT_0_pktCnt_row0_insert.apply();
				tb_IBLT_0_proto_row0_insert.apply();
				tb_IBLT_0_flowCnt_row0_insert.apply();
				tb_IBLT_0_srcIP_row1_insert.apply();
				tb_IBLT_0_dstIP_row1_insert.apply();
				tb_IBLT_0_ports_row1_insert.apply();
				tb_IBLT_0_pktCnt_row1_insert.apply();
				tb_IBLT_0_proto_row1_insert.apply();
				tb_IBLT_0_flowCnt_row1_insert.apply();
				tb_IBLT_1_srcIP_row0_insert.apply();
				tb_IBLT_1_dstIP_row0_insert.apply();
				tb_IBLT_1_ports_row0_insert.apply();
				tb_IBLT_1_pktCnt_row0_insert.apply();
				tb_IBLT_1_proto_row0_insert.apply();
				tb_IBLT_1_flowCnt_row0_insert.apply();
				tb_IBLT_1_srcIP_row1_insert.apply();
				tb_IBLT_1_dstIP_row1_insert.apply();
				tb_IBLT_1_ports_row1_insert.apply();
				tb_IBLT_1_pktCnt_row1_insert.apply();
				tb_IBLT_1_proto_row1_insert.apply();
				tb_IBLT_1_flowCnt_row1_insert.apply();
            }
        }
    }
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
