/* -*- P4_16 -*- */
/*
 * feature_engine.p4 — CRISP-Net 第 7a 步:在网特征引擎
 *
 * 目标:数据平面用 per-flow 寄存器在线算出与离线 data/processed/quic/features.csv **同口径**的
 * 40 维特征向量(QUIC=UDP,那 8 个恒 0 列由控制器置 0,本程序只算 32 个非零特征),
 * 在每个 W=32 包窗口满时经 Digest 上送 (flow_id, 特征)。
 *
 * 方法学声明:每包的方向 dir 与相对到达间隔 iat(微秒整数)由一个**自定义驱动头**携带,
 * 使特征计算可复现、不依赖 Mininet 回放的时序抖动 —— 本步验证的是**在网特征计算逻辑的正确性**,
 * 而非软件回放的时序保真度。**包长用真实包长**(ipv4.totalLen,驱动端把包合成成 pkts_size 字节)。
 *
 * P4 无浮点:iat 全程用整数微秒(µs),与离线参考的 µs 口径逐位一致。
 *
 * 流键:每条测试流分配唯一 srcPort,slot = srcPort - BASE_PORT(对受控流集是完美哈希、零碰撞);
 * 仍实现 fingerprint 守卫 + 碰撞计数器以证明零碰撞(真实哈希/碰撞解决留给 7b 资源预算)。
 */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_UDP  = 17;

#define NUM_FLOWS 256
#define W 32
#define DETAIL 8
#define BASE_PORT 10000
const bit<16> SMALL_TH = 200;
const bit<16> LARGE_TH = 1200;
const bit<32> DIGEST_ID = 1;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*********************** headers ***********************/
header ethernet_t { macAddr_t dstAddr; macAddr_t srcAddr; bit<16> etherType; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen;
    bit<16> identification; bit<3> flags; bit<13> fragOffset;
    bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum;
    ip4Addr_t srcAddr; ip4Addr_t dstAddr;
}
header udp_t { bit<16> srcPort; bit<16> dstPort; bit<16> length_; bit<16> checksum; }
// 驱动头(UDP 负载首部,12 字节)
header drv_t {
    bit<16> dir;      // 1=fwd(+1), 0=bwd(-1)
    bit<16> flags;    // 预留
    bit<32> iat_us;   // 相对到达间隔,微秒(已在驱动端 clip 到 6e7)
    bit<16> seq;      // 全局包序号(调试用)
    bit<16> pad;
}

struct metadata { }

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    drv_t      drv;
}

// Digest 上送结构(33 字段:flow_id + 32 个非零特征)
struct feat_digest_t {
    bit<16> flow_id;
    bit<16> len_1; bit<16> len_2; bit<16> len_3; bit<16> len_4;
    bit<16> len_5; bit<16> len_6; bit<16> len_7; bit<16> len_8;
    bit<8>  dir_1; bit<8>  dir_2; bit<8>  dir_3; bit<8>  dir_4;
    bit<8>  dir_5; bit<8>  dir_6; bit<8>  dir_7; bit<8>  dir_8;
    bit<32> iat_2; bit<32> iat_3; bit<32> iat_4; bit<32> iat_5;
    bit<32> iat_6; bit<32> iat_7; bit<32> iat_8;
    bit<32> sum_len; bit<16> min_len; bit<16> max_len;
    bit<16> n_fwd; bit<16> n_bwd; bit<16> n_small; bit<16> n_large;
    bit<32> iat_sum; bit<32> iat_max;
}

/*********************** registers ***********************/
register<bit<8>>(NUM_FLOWS)     r_count;
register<bit<16>>(NUM_FLOWS)    r_fp;       // fingerprint = srcPort, 0=空
register<bit<32>>(NUM_FLOWS)    r_sum;
register<bit<16>>(NUM_FLOWS)    r_min;
register<bit<16>>(NUM_FLOWS)    r_max;
register<bit<16>>(NUM_FLOWS)    r_nfwd;
register<bit<16>>(NUM_FLOWS)    r_nbwd;
register<bit<16>>(NUM_FLOWS)    r_nsmall;
register<bit<16>>(NUM_FLOWS)    r_nlarge;
register<bit<32>>(NUM_FLOWS)    r_iatsum;
register<bit<32>>(NUM_FLOWS)    r_iatmax;
register<bit<16>>(NUM_FLOWS*8)  r_len;
register<bit<8>>(NUM_FLOWS*8)   r_dir;
register<bit<32>>(NUM_FLOWS*8)  r_iat;
register<bit<32>>(1)            r_collisions;

/*********************** parser ***********************/
parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) { PROTO_UDP: parse_udp; default: accept; }
    }
    state parse_udp { packet.extract(hdr.udp); transition parse_drv; }
    state parse_drv { packet.extract(hdr.drv); transition accept; }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

/*********************** ingress ***********************/
control MyIngress(inout headers hdr, inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }

    apply {
        if (!hdr.drv.isValid()) { drop(); return; }

        bit<32> slot = (bit<32>)(hdr.udp.srcPort - BASE_PORT);

        // fingerprint 守卫(证明零碰撞)
        bit<16> fp;
        r_fp.read(fp, slot);
        if (fp != 0 && fp != hdr.udp.srcPort) {
            bit<32> col; r_collisions.read(col, 0); r_collisions.write(0, col + 1);
            drop(); return;
        }
        r_fp.write(slot, hdr.udp.srcPort);

        bit<8> cnt; r_count.read(cnt, slot);
        bit<32> pos = (bit<32>)cnt;

        bit<16> len = hdr.ipv4.totalLen;        // 真实包长
        bit<16> dirb = hdr.drv.dir;             // 1/0
        bit<32> iat = (pos == 0) ? 0 : hdr.drv.iat_us;  // 窗口首包 iat 不计

        // 前 8 包逐包明细
        if (pos < DETAIL) {
            bit<32> idx = slot * 8 + pos;
            r_len.write(idx, len);
            r_dir.write(idx, (bit<8>)dirb);
            r_iat.write(idx, iat);
        }

        // 窗口聚合(pos==0 初始化,否则增量)
        if (pos == 0) {
            r_sum.write(slot, (bit<32>)len);
            r_min.write(slot, len);
            r_max.write(slot, len);
            r_nfwd.write(slot, (dirb == 1) ? 16w1 : 16w0);
            r_nbwd.write(slot, (dirb == 0) ? 16w1 : 16w0);
            r_nsmall.write(slot, (len < SMALL_TH) ? 16w1 : 16w0);
            r_nlarge.write(slot, (len >= LARGE_TH) ? 16w1 : 16w0);
            r_iatsum.write(slot, 0);
            r_iatmax.write(slot, 0);
        } else {
            bit<32> s; r_sum.read(s, slot); r_sum.write(slot, s + (bit<32>)len);
            bit<16> mn; r_min.read(mn, slot); if (len < mn) { r_min.write(slot, len); }
            bit<16> mx; r_max.read(mx, slot); if (len > mx) { r_max.write(slot, len); }
            bit<16> a;  r_nfwd.read(a, slot);  if (dirb == 1) { r_nfwd.write(slot, a + 1); }
            bit<16> b;  r_nbwd.read(b, slot);  if (dirb == 0) { r_nbwd.write(slot, b + 1); }
            bit<16> c;  r_nsmall.read(c, slot); if (len < SMALL_TH) { r_nsmall.write(slot, c + 1); }
            bit<16> d;  r_nlarge.read(d, slot); if (len >= LARGE_TH) { r_nlarge.write(slot, d + 1); }
            bit<32> is; r_iatsum.read(is, slot); r_iatsum.write(slot, is + iat);
            bit<32> im; r_iatmax.read(im, slot); if (iat > im) { r_iatmax.write(slot, iat); }
        }

        cnt = cnt + 1;
        if (cnt == W) {
            // 组装并上送 digest
            feat_digest_t f;
            f.flow_id = hdr.udp.srcPort;
            bit<16> tl;
            r_len.read(tl, slot*8 + 0); f.len_1 = tl;
            r_len.read(tl, slot*8 + 1); f.len_2 = tl;
            r_len.read(tl, slot*8 + 2); f.len_3 = tl;
            r_len.read(tl, slot*8 + 3); f.len_4 = tl;
            r_len.read(tl, slot*8 + 4); f.len_5 = tl;
            r_len.read(tl, slot*8 + 5); f.len_6 = tl;
            r_len.read(tl, slot*8 + 6); f.len_7 = tl;
            r_len.read(tl, slot*8 + 7); f.len_8 = tl;
            bit<8> td;
            r_dir.read(td, slot*8 + 0); f.dir_1 = td;
            r_dir.read(td, slot*8 + 1); f.dir_2 = td;
            r_dir.read(td, slot*8 + 2); f.dir_3 = td;
            r_dir.read(td, slot*8 + 3); f.dir_4 = td;
            r_dir.read(td, slot*8 + 4); f.dir_5 = td;
            r_dir.read(td, slot*8 + 5); f.dir_6 = td;
            r_dir.read(td, slot*8 + 6); f.dir_7 = td;
            r_dir.read(td, slot*8 + 7); f.dir_8 = td;
            bit<32> ti;
            r_iat.read(ti, slot*8 + 1); f.iat_2 = ti;
            r_iat.read(ti, slot*8 + 2); f.iat_3 = ti;
            r_iat.read(ti, slot*8 + 3); f.iat_4 = ti;
            r_iat.read(ti, slot*8 + 4); f.iat_5 = ti;
            r_iat.read(ti, slot*8 + 5); f.iat_6 = ti;
            r_iat.read(ti, slot*8 + 6); f.iat_7 = ti;
            r_iat.read(ti, slot*8 + 7); f.iat_8 = ti;
            bit<32> agg32; bit<16> agg16;
            r_sum.read(agg32, slot);    f.sum_len = agg32;
            r_min.read(agg16, slot);    f.min_len = agg16;
            r_max.read(agg16, slot);    f.max_len = agg16;
            r_nfwd.read(agg16, slot);   f.n_fwd = agg16;
            r_nbwd.read(agg16, slot);   f.n_bwd = agg16;
            r_nsmall.read(agg16, slot); f.n_small = agg16;
            r_nlarge.read(agg16, slot); f.n_large = agg16;
            r_iatsum.read(agg32, slot); f.iat_sum = agg32;
            r_iatmax.read(agg32, slot); f.iat_max = agg32;
            digest<feat_digest_t>(DIGEST_ID, f);
            r_count.write(slot, 0);     // 重置进入下一个窗口
        } else {
            r_count.write(slot, cnt);
        }

        // 转发到端口 2(不影响特征;仅让包有去处)
        standard_metadata.egress_spec = 2;
    }
}

control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.drv);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
