#!/usr/bin/env python3
"""
rf_to_p4.py — CRISP-Net 第 7b 步:把 rf_pipeline 的 单RF10软投票+isotonic+τ 导出为 P4 程序 + 表项

生成:
  p4/rf_gate.p4                          (7a 特征引擎 + 10 棵树 range 表 + argmax + isotonic LUT 表 + τ 寄存器 + 决策 digest)
  data/processed/quic/rf_entries.json    (10 棵树叶子的 range 表项 + LUT range 表项 + tau8 + 校准用 feature key 名)

树编码:每棵树展开为"叶子 = 各路径特征的区间合取";一张 range 匹配表/棵,命中叶子的动作把该叶子的
8-bit 每类概率累加到 5 个累加器;10 棵树后 argmax(平票取低索引)得 pred 与软分数 score(0..2550);
score 经 isotonic LUT(range 表)映射到 8-bit 校准分数;与 τ(8-bit,寄存器)比较得 accept/defer。
"""
import os
import json
import numpy as np
import rf_pipeline as R

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(REPO, "data", "processed", "quic")
MAXV = (1 << 32) - 1
K = 5  # 类别数

# 32 个被使用的特征(与寄存器映射),供 tree 表 key
KEY_FEATS = R.FEATS[:0]  # 占位,下面填


def leaf_rules(est, p8):
    t = est.tree_
    rules = []

    def rec(node, bounds):
        if t.children_left[node] == -1:
            rules.append((dict(bounds), [int(x) for x in p8[node]]))
            return
        f = int(t.feature[node]); thr = float(t.threshold[node])
        T = int(np.floor(thr)); fname = R.FEATS[f]
        lo, hi = bounds.get(fname, (0, MAXV))
        lb = dict(bounds); lb[fname] = (lo, min(hi, T)); rec(t.children_left[node], lb)
        rb = dict(bounds); rb[fname] = (max(lo, T + 1), hi); rec(t.children_right[node], rb)
    rec(0, {})
    return rules


def build_entries(P):
    used = sorted({int(f) for est in P.rf.estimators_ for f in est.tree_.feature if f >= 0})
    key_feats = [R.FEATS[i] for i in used]
    trees = []
    for ti, est in enumerate(P.rf.estimators_):
        rules = leaf_rules(est, P.p8[ti])
        entries = []
        for prio, (bounds, params) in enumerate(rules, 1):
            match = {}
            for fname, (lo, hi) in bounds.items():
                if lo > 0 or hi < MAXV:
                    match[fname] = [int(lo), int(min(hi, MAXV))]
            entries.append({"prio": prio, "match": match, "params": params})
        trees.append(entries)
    # isotonic LUT -> 连续 score 段
    c = P.calib8; segs = []; s = 0
    for i in range(1, len(c) + 1):
        if i == len(c) or c[i] != c[s]:
            segs.append({"prio": len(segs) + 1, "lo": s, "hi": i - 1, "calib": int(c[s])}); s = i
    return key_feats, trees, segs


P4_TEMPLATE = r"""/* -*- P4_16 -*- */
/* rf_gate.p4 — CRISP-Net 7b:在网特征引擎 + RF10(软投票)+ isotonic LUT + τ 门控(自动生成,勿手改) */
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x0800; const bit<8> PROTO_UDP = 17;
#define NUM_FLOWS 256
#define W 32
#define DETAIL 8
#define BASE_PORT 10000
const bit<16> SMALL_TH = 200; const bit<16> LARGE_TH = 1200; const bit<32> DIGEST_ID = 1;
const bit<32> TAU8 = {tau8};   // 第6步 QUIC α=5% 的 8-bit 量化 τ̂(7b 静态常量;7d ACI 改用可写表)
typedef bit<48> macAddr_t; typedef bit<32> ip4Addr_t;

header ethernet_t {{ macAddr_t dstAddr; macAddr_t srcAddr; bit<16> etherType; }}
header ipv4_t {{ bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen; bit<16> identification;
  bit<3> flags; bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum; ip4Addr_t srcAddr; ip4Addr_t dstAddr; }}
header udp_t {{ bit<16> srcPort; bit<16> dstPort; bit<16> length_; bit<16> checksum; }}
header drv_t {{ bit<16> dir; bit<16> flags; bit<32> iat_us; bit<16> seq; bit<16> pad; }}

struct metadata {{
{meta_fields}
  bit<32> acc0; bit<32> acc1; bit<32> acc2; bit<32> acc3; bit<32> acc4;
  bit<32> score; bit<8> pred; bit<16> calib8; bit<8> accept; bit<1> win_done;
}}
struct headers {{ ethernet_t ethernet; ipv4_t ipv4; udp_t udp; drv_t drv; }}

struct dec_digest_t {{ bit<16> flow_id; bit<8> pred; bit<32> score; bit<16> calib8; bit<8> accept; }}
{seq_struct_decl}

register<bit<8>>(NUM_FLOWS) r_count;  register<bit<16>>(NUM_FLOWS) r_fp;
register<bit<32>>(NUM_FLOWS) r_sum; register<bit<16>>(NUM_FLOWS) r_min; register<bit<16>>(NUM_FLOWS) r_max;
register<bit<16>>(NUM_FLOWS) r_nfwd; register<bit<16>>(NUM_FLOWS) r_nbwd;
register<bit<16>>(NUM_FLOWS) r_nsmall; register<bit<16>>(NUM_FLOWS) r_nlarge;
register<bit<32>>(NUM_FLOWS) r_iatsum; register<bit<32>>(NUM_FLOWS) r_iatmax;
register<bit<16>>(NUM_FLOWS*{det_size}) r_len; register<bit<8>>(NUM_FLOWS*{det_size}) r_dir; register<bit<32>>(NUM_FLOWS*{det_size}) r_iat;
register<bit<32>>(1) r_collisions;

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t sm) {{
  state start {{ transition parse_ethernet; }}
  state parse_ethernet {{ packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {{ TYPE_IPV4: parse_ipv4; default: accept; }} }}
  state parse_ipv4 {{ packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {{ PROTO_UDP: parse_udp; default: accept; }} }}
  state parse_udp {{ packet.extract(hdr.udp); transition parse_drv; }}
  state parse_drv {{ packet.extract(hdr.drv); transition accept; }}
}}
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {{ apply {{ }} }}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {{
  action drop() {{ mark_to_drop(sm); }}
  action add_leaf(bit<32> p0, bit<32> p1, bit<32> p2, bit<32> p3, bit<32> p4) {{
    meta.acc0 = meta.acc0 + p0; meta.acc1 = meta.acc1 + p1; meta.acc2 = meta.acc2 + p2;
    meta.acc3 = meta.acc3 + p3; meta.acc4 = meta.acc4 + p4;
  }}
  action set_calib(bit<16> c) {{ meta.calib8 = c; }}
{tree_tables}
  table isotonic_lut {{
    key = {{ meta.score : range; }}
    actions = {{ set_calib; NoAction; }}
    default_action = NoAction(); size = 256;
  }}
  apply {{
    if (!hdr.drv.isValid()) {{ drop(); return; }}
    bit<32> slot = (bit<32>)(hdr.udp.srcPort - BASE_PORT);
    bit<16> fp; r_fp.read(fp, slot);
    if (fp != 0 && fp != hdr.udp.srcPort) {{ bit<32> col; r_collisions.read(col,0); r_collisions.write(0,col+1); drop(); return; }}
    r_fp.write(slot, hdr.udp.srcPort);
    bit<8> cnt; r_count.read(cnt, slot); bit<32> pos = (bit<32>)cnt;
    bit<16> len = hdr.ipv4.totalLen; bit<16> dirb = hdr.drv.dir;
    bit<32> iat = (pos == 0) ? 0 : hdr.drv.iat_us;
    if (pos < {det_size}) {{ bit<32> idx = slot*{det_size} + pos; r_len.write(idx,len); r_dir.write(idx,(bit<8>)dirb); r_iat.write(idx,iat); }}
    if (pos == 0) {{
      r_sum.write(slot,(bit<32>)len); r_min.write(slot,len); r_max.write(slot,len);
      r_nfwd.write(slot,(dirb==1)?16w1:16w0); r_nbwd.write(slot,(dirb==0)?16w1:16w0);
      r_nsmall.write(slot,(len<SMALL_TH)?16w1:16w0); r_nlarge.write(slot,(len>=LARGE_TH)?16w1:16w0);
      r_iatsum.write(slot,0); r_iatmax.write(slot,0);
    }} else {{
      bit<32> s; r_sum.read(s,slot); r_sum.write(slot,s+(bit<32>)len);
      bit<16> mn; r_min.read(mn,slot); if(len<mn){{r_min.write(slot,len);}}
      bit<16> mx; r_max.read(mx,slot); if(len>mx){{r_max.write(slot,len);}}
      bit<16> a; r_nfwd.read(a,slot); if(dirb==1){{r_nfwd.write(slot,a+1);}}
      bit<16> b; r_nbwd.read(b,slot); if(dirb==0){{r_nbwd.write(slot,b+1);}}
      bit<16> c2; r_nsmall.read(c2,slot); if(len<SMALL_TH){{r_nsmall.write(slot,c2+1);}}
      bit<16> d; r_nlarge.read(d,slot); if(len>=LARGE_TH){{r_nlarge.write(slot,d+1);}}
      bit<32> is; r_iatsum.read(is,slot); r_iatsum.write(slot,is+iat);
      bit<32> im; r_iatmax.read(im,slot); if(iat>im){{r_iatmax.write(slot,iat);}}
    }}
    cnt = cnt + 1;
    if (cnt == W) {{
      // 读回 40 维特征到 metadata(数据面单位:dir 0/1,iat µs)
{load_feats}
      // RF:10 棵树累加 8-bit 概率
      meta.acc0=0; meta.acc1=0; meta.acc2=0; meta.acc3=0; meta.acc4=0;
{tree_applies}
      // argmax(平票取低索引)
      meta.pred=0; meta.score=meta.acc0;
      if (meta.acc1 > meta.score) {{ meta.pred=1; meta.score=meta.acc1; }}
      if (meta.acc2 > meta.score) {{ meta.pred=2; meta.score=meta.acc2; }}
      if (meta.acc3 > meta.score) {{ meta.pred=3; meta.score=meta.acc3; }}
      if (meta.acc4 > meta.score) {{ meta.pred=4; meta.score=meta.acc4; }}
      // isotonic LUT + τ 比较
      meta.calib8 = 0; isotonic_lut.apply();
      meta.accept = (((bit<32>)meta.calib8) >= TAU8) ? 8w1 : 8w0;
      dec_digest_t dd;
      dd.flow_id = hdr.udp.srcPort; dd.pred = meta.pred; dd.score = meta.score;
      dd.calib8 = meta.calib8; dd.accept = meta.accept;
{decision_emit}
      r_count.write(slot, 0);
    }} else {{ r_count.write(slot, cnt); }}
    sm.egress_spec = 2;
  }}
}}
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {{ apply {{ }} }}
control MyComputeChecksum(inout headers hdr, inout metadata meta) {{ apply {{ }} }}
control MyDeparser(packet_out packet, in headers hdr) {{
  apply {{ packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.udp); packet.emit(hdr.drv); }}
}}
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
"""

# 特征名 -> 寄存器读取语句(det 为每流明细槽数 8 或 32)
def load_feats_code(key_feats, det=8):
    lines = []
    for i in range(8):
        lines.append("      {{ bit<16> v; r_len.read(v, slot*%d + %d); meta.f_len_%d = (bit<32>)v; }}" % (det, i, i + 1))
        lines.append("      {{ bit<8> v; r_dir.read(v, slot*%d + %d); meta.f_dir_%d = (bit<32>)v; }}" % (det, i, i + 1))
    for i in range(1, 8):
        lines.append("      {{ bit<32> v; r_iat.read(v, slot*%d + %d); meta.f_iat_%d = v; }}" % (det, i, i + 1))
    aggreads = [("f_sum_len", "r_sum", 32), ("f_min_len", "r_min", 16), ("f_max_len", "r_max", 16),
                ("f_n_fwd", "r_nfwd", 16), ("f_n_bwd", "r_nbwd", 16), ("f_n_small", "r_nsmall", 16),
                ("f_n_large", "r_nlarge", 16), ("f_iat_sum", "r_iatsum", 32), ("f_iat_max", "r_iatmax", 32)]
    for fn, reg, wbits in aggreads:
        lines.append("      {{ bit<%d> v; %s.read(v, slot); meta.%s = (bit<32>)v; }}" % (wbits, reg, fn))
    return "\n".join(lines)


def gen(closed_loop=False, tau_override=None):
    P = R.RFGatePipeline(PROC)
    key_feats, trees, segs = build_entries(P)
    # metadata 特征字段(仅被使用的 32 个,均 bit<32>)
    meta_fields = "\n".join("  bit<32> f_%s;" % f for f in key_feats)
    key_block = "\n".join("      meta.f_%s : range;" % f for f in key_feats)
    tree_tables = ""
    for ti in range(len(trees)):
        tree_tables += (
            "  table tree_%d {\n    key = {\n%s\n    }\n"
            "    actions = { add_leaf; NoAction; }\n    default_action = NoAction(); size = 4096;\n  }\n"
            % (ti, key_block))
    tree_applies = "\n".join("      tree_%d.apply();" % ti for ti in range(len(trees)))

    # 决策模式与闭环模式共用
    det = 32 if closed_loop else 8
    if closed_loop:
        # seq_digest_t: flow_id + len_1..32(16) + dir_1..32(8) + iat_1..32(32)
        sf = ["bit<16> flow_id;"]
        sf += ["bit<16> slen_%d;" % i for i in range(1, 33)]
        sf += ["bit<8> sdir_%d;" % i for i in range(1, 33)]
        sf += ["bit<32> siat_%d;" % i for i in range(1, 33)]
        seq_struct_decl = "struct seq_digest_t { " + " ".join(sf) + " }"
        rd = ["      seq_digest_t sq; sq.flow_id = hdr.udp.srcPort;"]
        for i in range(32):
            rd.append("      {{ bit<16> v; r_len.read(v, slot*32 + %d); sq.slen_%d = v; }}" % (i, i + 1))
            rd.append("      {{ bit<8> v; r_dir.read(v, slot*32 + %d); sq.sdir_%d = v; }}" % (i, i + 1))
            rd.append("      {{ bit<32> v; r_iat.read(v, slot*32 + %d); sq.siat_%d = v; }}" % (i, i + 1))
        rd.append("        digest<seq_digest_t>(DIGEST_SEQ, sq);")
        # 每窗口恰一条 digest:accept->dec,defer->seq(显式 if/else,不依赖 bmv2"末次 digest 生效")
        decision_emit = ("      if (meta.accept == 1) { digest<dec_digest_t>(DIGEST_ID, dd); }\n"
                         "      else {\n" + "\n".join(rd) + "\n      }")
    else:
        seq_struct_decl = ""
        decision_emit = "      digest<dec_digest_t>(DIGEST_ID, dd);"

    tau8 = tau_override if tau_override is not None else int(P.tau8)
    p4 = P4_TEMPLATE.format(meta_fields=meta_fields, tree_tables=tree_tables,
                            load_feats=load_feats_code(key_feats, det), tree_applies=tree_applies,
                            tau8=tau8, det_size=det, seq_struct_decl=seq_struct_decl,
                            decision_emit=decision_emit)
    if closed_loop:
        p4 = p4.replace("const bit<32> DIGEST_ID = 1;",
                        "const bit<32> DIGEST_ID = 1; const bit<32> DIGEST_SEQ = 2;")
    out_p4 = os.path.join(REPO, "p4", "rf_gate_cl.p4" if closed_loop else "rf_gate.p4")
    with open(out_p4, "w") as f:
        f.write(p4)
    entries = {"tau8": int(tau8), "key_feats": key_feats,
               "classes": P.rf_classes, "trees": trees, "lut": segs, "feats_order": R.FEATS}
    epath = os.path.join(PROC, "rf_entries_cl.json" if closed_loop else "rf_entries.json")
    with open(epath, "w") as f:
        json.dump(entries, f)
    print("[gen] %s 写出;%d 树, 叶子 %d, LUT %d, tau8=%d, key特征 %d, det=%d"
          % (os.path.basename(out_p4), len(trees), sum(len(t) for t in trees),
             len(segs), tau8, len(key_feats), det))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--closed-loop", action="store_true")
    ap.add_argument("--tau", type=int, default=None, help="覆盖 τ̂₈(7c 用 Part A 修正值)")
    a = ap.parse_args()
    gen(closed_loop=a.closed_loop, tau_override=a.tau)
