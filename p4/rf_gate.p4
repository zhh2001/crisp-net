/* -*- P4_16 -*- */
/* rf_gate.p4 — CRISP-Net 7b:在网特征引擎 + RF10(软投票)+ isotonic LUT + τ 门控(自动生成,勿手改) */
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x0800; const bit<8> PROTO_UDP = 17;
#define NUM_FLOWS 256
#define W 32
#define DETAIL 8
#define BASE_PORT 10000
const bit<16> SMALL_TH = 200; const bit<16> LARGE_TH = 1200; const bit<32> DIGEST_ID = 1;
const bit<32> TAU8 = 228;   // 第6步 QUIC α=5% 的 8-bit 量化 τ̂(7b 静态常量;7d ACI 改用可写表)
typedef bit<48> macAddr_t; typedef bit<32> ip4Addr_t;

header ethernet_t { macAddr_t dstAddr; macAddr_t srcAddr; bit<16> etherType; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen; bit<16> identification;
  bit<3> flags; bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum; ip4Addr_t srcAddr; ip4Addr_t dstAddr; }
header udp_t { bit<16> srcPort; bit<16> dstPort; bit<16> length_; bit<16> checksum; }
header drv_t { bit<16> dir; bit<16> flags; bit<32> iat_us; bit<16> seq; bit<16> pad; }

struct metadata {
  bit<32> f_len_1;
  bit<32> f_dir_1;
  bit<32> f_len_2;
  bit<32> f_dir_2;
  bit<32> f_len_3;
  bit<32> f_dir_3;
  bit<32> f_len_4;
  bit<32> f_dir_4;
  bit<32> f_len_5;
  bit<32> f_dir_5;
  bit<32> f_len_6;
  bit<32> f_dir_6;
  bit<32> f_len_7;
  bit<32> f_dir_7;
  bit<32> f_len_8;
  bit<32> f_dir_8;
  bit<32> f_iat_2;
  bit<32> f_iat_3;
  bit<32> f_iat_4;
  bit<32> f_iat_5;
  bit<32> f_iat_6;
  bit<32> f_iat_7;
  bit<32> f_iat_8;
  bit<32> f_sum_len;
  bit<32> f_min_len;
  bit<32> f_max_len;
  bit<32> f_n_fwd;
  bit<32> f_n_bwd;
  bit<32> f_n_small;
  bit<32> f_n_large;
  bit<32> f_iat_sum;
  bit<32> f_iat_max;
  bit<32> acc0; bit<32> acc1; bit<32> acc2; bit<32> acc3; bit<32> acc4;
  bit<32> score; bit<8> pred; bit<16> calib8; bit<8> accept; bit<1> win_done;
}
struct headers { ethernet_t ethernet; ipv4_t ipv4; udp_t udp; drv_t drv; }

struct dec_digest_t { bit<16> flow_id; bit<8> pred; bit<32> score; bit<16> calib8; bit<8> accept; }

register<bit<8>>(NUM_FLOWS) r_count;  register<bit<16>>(NUM_FLOWS) r_fp;
register<bit<32>>(NUM_FLOWS) r_sum; register<bit<16>>(NUM_FLOWS) r_min; register<bit<16>>(NUM_FLOWS) r_max;
register<bit<16>>(NUM_FLOWS) r_nfwd; register<bit<16>>(NUM_FLOWS) r_nbwd;
register<bit<16>>(NUM_FLOWS) r_nsmall; register<bit<16>>(NUM_FLOWS) r_nlarge;
register<bit<32>>(NUM_FLOWS) r_iatsum; register<bit<32>>(NUM_FLOWS) r_iatmax;
register<bit<16>>(NUM_FLOWS*8) r_len; register<bit<8>>(NUM_FLOWS*8) r_dir; register<bit<32>>(NUM_FLOWS*8) r_iat;
register<bit<32>>(1) r_collisions;

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t sm) {
  state start { transition parse_ethernet; }
  state parse_ethernet { packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; } }
  state parse_ipv4 { packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) { PROTO_UDP: parse_udp; default: accept; } }
  state parse_udp { packet.extract(hdr.udp); transition parse_drv; }
  state parse_drv { packet.extract(hdr.drv); transition accept; }
}
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
  action drop() { mark_to_drop(sm); }
  action add_leaf(bit<32> p0, bit<32> p1, bit<32> p2, bit<32> p3, bit<32> p4) {
    meta.acc0 = meta.acc0 + p0; meta.acc1 = meta.acc1 + p1; meta.acc2 = meta.acc2 + p2;
    meta.acc3 = meta.acc3 + p3; meta.acc4 = meta.acc4 + p4;
  }
  action set_calib(bit<16> c) { meta.calib8 = c; }
  table tree_0 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_1 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_2 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_3 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_4 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_5 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_6 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_7 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_8 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }
  table tree_9 {
    key = {
      meta.f_len_1 : range;
      meta.f_dir_1 : range;
      meta.f_len_2 : range;
      meta.f_dir_2 : range;
      meta.f_len_3 : range;
      meta.f_dir_3 : range;
      meta.f_len_4 : range;
      meta.f_dir_4 : range;
      meta.f_len_5 : range;
      meta.f_dir_5 : range;
      meta.f_len_6 : range;
      meta.f_dir_6 : range;
      meta.f_len_7 : range;
      meta.f_dir_7 : range;
      meta.f_len_8 : range;
      meta.f_dir_8 : range;
      meta.f_iat_2 : range;
      meta.f_iat_3 : range;
      meta.f_iat_4 : range;
      meta.f_iat_5 : range;
      meta.f_iat_6 : range;
      meta.f_iat_7 : range;
      meta.f_iat_8 : range;
      meta.f_sum_len : range;
      meta.f_min_len : range;
      meta.f_max_len : range;
      meta.f_n_fwd : range;
      meta.f_n_bwd : range;
      meta.f_n_small : range;
      meta.f_n_large : range;
      meta.f_iat_sum : range;
      meta.f_iat_max : range;
    }
    actions = { add_leaf; NoAction; }
    default_action = NoAction(); size = 4096;
  }

  table isotonic_lut {
    key = { meta.score : range; }
    actions = { set_calib; NoAction; }
    default_action = NoAction(); size = 256;
  }
  apply {
    if (!hdr.drv.isValid()) { drop(); return; }
    bit<32> slot = (bit<32>)(hdr.udp.srcPort - BASE_PORT);
    bit<16> fp; r_fp.read(fp, slot);
    if (fp != 0 && fp != hdr.udp.srcPort) { bit<32> col; r_collisions.read(col,0); r_collisions.write(0,col+1); drop(); return; }
    r_fp.write(slot, hdr.udp.srcPort);
    bit<8> cnt; r_count.read(cnt, slot); bit<32> pos = (bit<32>)cnt;
    bit<16> len = hdr.ipv4.totalLen; bit<16> dirb = hdr.drv.dir;
    bit<32> iat = (pos == 0) ? 0 : hdr.drv.iat_us;
    if (pos < DETAIL) { bit<32> idx = slot*8 + pos; r_len.write(idx,len); r_dir.write(idx,(bit<8>)dirb); r_iat.write(idx,iat); }
    if (pos == 0) {
      r_sum.write(slot,(bit<32>)len); r_min.write(slot,len); r_max.write(slot,len);
      r_nfwd.write(slot,(dirb==1)?16w1:16w0); r_nbwd.write(slot,(dirb==0)?16w1:16w0);
      r_nsmall.write(slot,(len<SMALL_TH)?16w1:16w0); r_nlarge.write(slot,(len>=LARGE_TH)?16w1:16w0);
      r_iatsum.write(slot,0); r_iatmax.write(slot,0);
    } else {
      bit<32> s; r_sum.read(s,slot); r_sum.write(slot,s+(bit<32>)len);
      bit<16> mn; r_min.read(mn,slot); if(len<mn){r_min.write(slot,len);}
      bit<16> mx; r_max.read(mx,slot); if(len>mx){r_max.write(slot,len);}
      bit<16> a; r_nfwd.read(a,slot); if(dirb==1){r_nfwd.write(slot,a+1);}
      bit<16> b; r_nbwd.read(b,slot); if(dirb==0){r_nbwd.write(slot,b+1);}
      bit<16> c2; r_nsmall.read(c2,slot); if(len<SMALL_TH){r_nsmall.write(slot,c2+1);}
      bit<16> d; r_nlarge.read(d,slot); if(len>=LARGE_TH){r_nlarge.write(slot,d+1);}
      bit<32> is; r_iatsum.read(is,slot); r_iatsum.write(slot,is+iat);
      bit<32> im; r_iatmax.read(im,slot); if(iat>im){r_iatmax.write(slot,iat);}
    }
    cnt = cnt + 1;
    if (cnt == W) {
      // 读回 40 维特征到 metadata(数据面单位:dir 0/1,iat µs)
      {{ bit<16> v; r_len.read(v, slot*8 + 0); meta.f_len_1 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 0); meta.f_dir_1 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 1); meta.f_len_2 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 1); meta.f_dir_2 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 2); meta.f_len_3 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 2); meta.f_dir_3 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 3); meta.f_len_4 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 3); meta.f_dir_4 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 4); meta.f_len_5 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 4); meta.f_dir_5 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 5); meta.f_len_6 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 5); meta.f_dir_6 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 6); meta.f_len_7 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 6); meta.f_dir_7 = (bit<32>)v; }}
      {{ bit<16> v; r_len.read(v, slot*8 + 7); meta.f_len_8 = (bit<32>)v; }}
      {{ bit<8> v; r_dir.read(v, slot*8 + 7); meta.f_dir_8 = (bit<32>)v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 1); meta.f_iat_2 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 2); meta.f_iat_3 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 3); meta.f_iat_4 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 4); meta.f_iat_5 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 5); meta.f_iat_6 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 6); meta.f_iat_7 = v; }}
      {{ bit<32> v; r_iat.read(v, slot*8 + 7); meta.f_iat_8 = v; }}
      {{ bit<32> v; r_sum.read(v, slot); meta.f_sum_len = (bit<32>)v; }}
      {{ bit<16> v; r_min.read(v, slot); meta.f_min_len = (bit<32>)v; }}
      {{ bit<16> v; r_max.read(v, slot); meta.f_max_len = (bit<32>)v; }}
      {{ bit<16> v; r_nfwd.read(v, slot); meta.f_n_fwd = (bit<32>)v; }}
      {{ bit<16> v; r_nbwd.read(v, slot); meta.f_n_bwd = (bit<32>)v; }}
      {{ bit<16> v; r_nsmall.read(v, slot); meta.f_n_small = (bit<32>)v; }}
      {{ bit<16> v; r_nlarge.read(v, slot); meta.f_n_large = (bit<32>)v; }}
      {{ bit<32> v; r_iatsum.read(v, slot); meta.f_iat_sum = (bit<32>)v; }}
      {{ bit<32> v; r_iatmax.read(v, slot); meta.f_iat_max = (bit<32>)v; }}
      // RF:10 棵树累加 8-bit 概率
      meta.acc0=0; meta.acc1=0; meta.acc2=0; meta.acc3=0; meta.acc4=0;
      tree_0.apply();
      tree_1.apply();
      tree_2.apply();
      tree_3.apply();
      tree_4.apply();
      tree_5.apply();
      tree_6.apply();
      tree_7.apply();
      tree_8.apply();
      tree_9.apply();
      // argmax(平票取低索引)
      meta.pred=0; meta.score=meta.acc0;
      if (meta.acc1 > meta.score) { meta.pred=1; meta.score=meta.acc1; }
      if (meta.acc2 > meta.score) { meta.pred=2; meta.score=meta.acc2; }
      if (meta.acc3 > meta.score) { meta.pred=3; meta.score=meta.acc3; }
      if (meta.acc4 > meta.score) { meta.pred=4; meta.score=meta.acc4; }
      // isotonic LUT + τ 比较
      meta.calib8 = 0; isotonic_lut.apply();
      meta.accept = (((bit<32>)meta.calib8) >= TAU8) ? 8w1 : 8w0;
      dec_digest_t dd;
      dd.flow_id = hdr.udp.srcPort; dd.pred = meta.pred; dd.score = meta.score;
      dd.calib8 = meta.calib8; dd.accept = meta.accept;
      digest<dec_digest_t>(DIGEST_ID, dd);
      r_count.write(slot, 0);
    } else { r_count.write(slot, cnt); }
    sm.egress_spec = 2;
  }
}
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) {
  apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.udp); packet.emit(hdr.drv); }
}
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
