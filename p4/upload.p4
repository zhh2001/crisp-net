/* -*- P4_16 -*- */
/*
 * upload.p4 — CRISP-Net 第 2 步 / 轨道 2:数据平面 -> host 上送通道
 *
 * 在 l3fwd(Ethernet/IPv4 + ipv4_lpm 转发 + 出口计数器)基础上,增加把"被标记的流"
 * 上交给 host 控制器的两种机制,为 CRISP 的"模糊流上交 DNN 专家"铺路:
 *
 *   (a) PacketIn  : 经 CPU port + clone(I2E) 把一份拷贝送到控制器,
 *                   出口处 prepend 一个 @controller_header("packet_in") 头,携带流特征。
 *   (b) Digest    : 用 v1model digest extern 上送一个小结构体(5 元组 + 包长 + 入端口),
 *                   不送整包,经 P4Runtime DigestList 到控制器。
 *
 * 触发条件(平凡):一张 monitor_flows 表(key = ipv4.dstAddr),命中即标记上送;
 * 控制器灌入要监控的目的 IP 即可。被标记的包同时触发 PacketIn 与 Digest,
 * 便于分别统计两种机制的收到率。原始包仍正常 L3 转发(clone 是拷贝,不影响转发)。
 *
 * 运行:simple_switch_grpc 必须带 --cpu-port 510;clone session 由控制器经 PRE 配置。
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP  = 6;
const bit<8>  PROTO_UDP  = 17;

#define CPU_PORT 510
const int CPU_PORT_CLONE_SESSION_ID = 57;
const int FL_CLONE_I2E = 1;          // field_list id,用于 clone 时保留 meta
const bit<32> DIGEST_RECEIVER = 1;   // digest id(任意,控制器据 p4info 解析)

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*********************** H E A D E R S ***********************/

@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;   // 控制器指定回注的出端口
    bit<16> pad;
}

@controller_header("packet_in")
header packet_in_header_t {
    // 上送给控制器的"流特征向量"(PacketIn 路径)
    bit<16> ingress_port;
    bit<8>  protocol;
    bit<8>  reason;        // 1 = monitored-flow
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> pkt_len;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    // 其余字段本步用不到,不解析
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// digest 上送的结构体(Digest 路径)——一条"流特征记录"
struct flow_digest_t {
    bit<16> ingress_port;
    bit<8>  protocol;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> pkt_len;
}

struct metadata {
    @field_list(FL_CLONE_I2E) bit<16> ingress_port;
    @field_list(FL_CLONE_I2E) bit<8>  protocol;
    @field_list(FL_CLONE_I2E) bit<16> src_port;
    @field_list(FL_CLONE_I2E) bit<16> dst_port;
    @field_list(FL_CLONE_I2E) bit<16> pkt_len;
    bit<1>  do_upload;
}

struct headers {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
}

/*********************** P A R S E R ***********************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;   // 来自控制器的 PacketOut
            default:  parse_ethernet;
        }
    }
    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*********************** I N G R E S S ***********************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(256, CounterType.packets) upload_counter;   // 上送触发次数(按入端口)

    action drop() { mark_to_drop(standard_metadata); }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    action mark_upload() { meta.do_upload = 1; }

    table monitor_flows {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { mark_upload; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        // 1) 控制器回注的 PacketOut:按指定端口发出,剥掉 packet_out 头
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = (bit<9>) hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            return;
        }

        if (hdr.ipv4.isValid()) {
            // 收集"流特征"到 meta(供 clone/digest/packet_in 使用)
            meta.ingress_port = (bit<16>) standard_metadata.ingress_port;
            meta.protocol     = hdr.ipv4.protocol;
            meta.pkt_len      = hdr.ipv4.totalLen;
            if (hdr.tcp.isValid()) {
                meta.src_port = hdr.tcp.srcPort;
                meta.dst_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                meta.src_port = hdr.udp.srcPort;
                meta.dst_port = hdr.udp.dstPort;
            } else {
                meta.src_port = 0;
                meta.dst_port = 0;
            }

            // 2) 正常 L3 转发
            ipv4_lpm.apply();

            // 3) 判定是否上送
            monitor_flows.apply();
            if (meta.do_upload == 1) {
                upload_counter.count((bit<32>) standard_metadata.ingress_port);

                // (b) Digest 路径:上送一条流特征记录(不送整包)
                flow_digest_t d;
                d.ingress_port = meta.ingress_port;
                d.protocol     = hdr.ipv4.protocol;
                d.src_addr     = hdr.ipv4.srcAddr;
                d.dst_addr     = hdr.ipv4.dstAddr;
                d.src_port     = meta.src_port;
                d.dst_port     = meta.dst_port;
                d.pkt_len      = hdr.ipv4.totalLen;
                digest<flow_digest_t>(DIGEST_RECEIVER, d);

                // (a) PacketIn 路径:clone 一份到 CPU(原包继续正常转发)
                clone_preserving_field_list(CloneType.I2E,
                    (bit<32>) CPU_PORT_CLONE_SESSION_ID, FL_CLONE_I2E);
            }
        } else {
            drop();
        }
    }
}

/*********************** E G R E S S ***********************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    counter(256, CounterType.packets) fwd_pkt_counter;

    action add_packet_in_header() {
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = meta.ingress_port;
        hdr.packet_in.protocol     = meta.protocol;
        hdr.packet_in.reason       = 1;
        hdr.packet_in.src_addr     = hdr.ipv4.srcAddr;
        hdr.packet_in.dst_addr     = hdr.ipv4.dstAddr;
        hdr.packet_in.src_port     = meta.src_port;
        hdr.packet_in.dst_port     = meta.dst_port;
        hdr.packet_in.pkt_len      = meta.pkt_len;
    }

    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            // 这是送往控制器的 clone 拷贝:prepend packet_in 头(携带流特征)
            add_packet_in_header();
        } else if (hdr.ipv4.isValid()) {
            // 正常转发的包:按出端口计数
            fwd_pkt_counter.count((bit<32>) standard_metadata.egress_port);
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

/*********************** D E P A R S E R ***********************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);   // 只对送往 CPU 的拷贝有效(其余 invalid)
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
