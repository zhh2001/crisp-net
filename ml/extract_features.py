#!/usr/bin/env python3
"""
extract_features.py — CRISP-Net 第 2 步 / 轨道 1:受限特征提取 + train/calib/test 划分

数据集:Encrypted VPN Dataset (Zenodo 7301756),JSON,按 {VPN/<协议>|Non VPN}/<类型>.json
组织,每个文件是若干"5 元组双向流(biflow)"的数组,每条流含 x_packets(逐包记录:
带符号 bytes=包长&方向、timestamp、tcp_flags、ports)。

由于每文件 biflow 很少但极长,采用 ETC 常用做法:把每条 biflow 切成 **W 包定长窗口**,
每个窗口作为一个分类样本(也更贴近"在网树":交换机基于一段窗口的统计做推理)。
标签 = 流量类型(ssh/meet/mail/streaming/non_streaming)。

**只抽取 bmv2 v1model 数据平面现实可计算的特征**(见 feature_manifest.csv 的逐特征 P4 标注):
整数运算、有限窗口、可用寄存器维护的累计量;不使用除法(均值等)、不使用无界循环。

防泄漏:**按 biflow 划分** train/calib/test(同一条流的所有窗口进同一份);固定随机种子。
calibration 份本步只创建、存盘、绝不参与训练/评估。
"""
import os
import sys
import json
import zipfile
import random
import argparse
from collections import defaultdict, Counter
from datetime import datetime

import ijson
import numpy as np
import pandas as pd

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP = os.path.join(REPO, "data", "raw", "encrypted_vpn_dataset.zip")
ROOT = "encrypted_vpn_dataset"

LABELS = ["ssh", "meet", "mail", "streaming", "non_streaming"]
SOURCES = ["VPN/SSTP", "VPN/OpenVPN", "VPN/PPTP", "VPN/L2TP",
           "VPN/WireGuard", "VPN/L2TP IPsec", "Non VPN"]

W = 32                 # 每个样本=一段 W 包的窗口(段)
DETAIL = 8             # 仅对前 DETAIL 个包保留逐包明细(少量寄存器即可,P4 最现实)
SMALL_TH = 200         # 小包阈值(字节)
LARGE_TH = 1200        # 大包阈值(接近 MTU)
K_FLOWS_PER_FILE = 150 # 每文件最多取多少条 biflow(流式提前停止)
MAX_WIN_PER_FLOW = 12  # 每条 biflow 最多切多少窗口(用前 W*MAX_WIN 个包),控制类间平衡
IAT_CLIP_MS = 60000.0

_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def parse_ts(s):
    try:
        return datetime.strptime(s, _TS_FMT).timestamp()
    except Exception:
        return None


def tcp_flag_bits(flagstr):
    # tcp_flags 形如 "011000",位序 [URG,ACK,PSH,RST,SYN,FIN]
    if not flagstr or len(flagstr) < 6:
        return dict(urg=0, ack=0, psh=0, rst=0, syn=0, fin=0)
    b = flagstr[-6:]
    return dict(urg=int(b[0]), ack=int(b[1]), psh=int(b[2]),
                rst=int(b[3]), syn=int(b[4]), fin=int(b[5]))


def window_features(pkts):
    """对 W 包的段计算受限特征:前 DETAIL 包逐包明细 + 全段累计统计(均 P4 可计算)。"""
    lens, dirs, ts = [], [], []
    for p in pkts:
        try:
            b = int(p["bytes"])
        except Exception:
            b = 0
        lens.append(abs(b))
        dirs.append(1 if b > 0 else (-1 if b < 0 else 0))
        ts.append(parse_ts(p.get("timestamp_start", "")))

    feat = {}
    # --- 前 DETAIL 包逐包明细(少量寄存器)---
    for k in range(DETAIL):
        feat["len_%d" % (k + 1)] = lens[k]
        feat["dir_%d" % (k + 1)] = dirs[k]
    for k in range(1, DETAIL):
        if ts[k] is not None and ts[k - 1] is not None:
            d = (ts[k] - ts[k - 1]) * 1000.0
            feat["iat_%d" % (k + 1)] = float(min(max(d, 0.0), IAT_CLIP_MS))
        else:
            feat["iat_%d" % (k + 1)] = 0.0

    # --- 全段(W 包)累计统计(寄存器/计数器可维护)---
    feat["sum_len"] = int(sum(lens))
    feat["min_len"] = int(min(lens))
    feat["max_len"] = int(max(lens))
    feat["n_fwd"] = int(sum(1 for d in dirs if d > 0))
    feat["n_bwd"] = int(sum(1 for d in dirs if d < 0))
    feat["n_small"] = int(sum(1 for x in lens if x < SMALL_TH))      # 小包数
    feat["n_large"] = int(sum(1 for x in lens if x >= LARGE_TH))     # 近 MTU 大包数
    # 段内相邻包间隔统计
    iats = []
    for k in range(1, len(ts)):
        if ts[k] is not None and ts[k - 1] is not None:
            iats.append(min(max((ts[k] - ts[k - 1]) * 1000.0, 0.0), IAT_CLIP_MS))
    feat["iat_sum"] = float(sum(iats)) if iats else 0.0
    feat["iat_max"] = float(max(iats)) if iats else 0.0

    # --- 首包 TCP flags ---
    fb = tcp_flag_bits(pkts[0].get("tcp_flags", ""))
    feat["syn0"] = fb["syn"]; feat["ack0"] = fb["ack"]; feat["fin0"] = fb["fin"]
    feat["rst0"] = fb["rst"]; feat["psh0"] = fb["psh"]
    return feat


def flow_meta(flow):
    proto = str(flow.get("ip_proto", "")).lower()
    proto_tcp = 1 if proto == "tcp" else 0
    try:
        pdst = int(flow.get("port_dst", 0))
    except Exception:
        pdst = 0
    try:
        psrc = int(flow.get("port_src", 0))
    except Exception:
        psrc = 0
    return proto_tcp, psrc, pdst


def extract():
    rows = []
    z = zipfile.ZipFile(ZIP)
    per_source_label_flows = Counter()
    for label in LABELS:
        for src in SOURCES:
            name = "%s/%s/%s.json" % (ROOT, src, label)
            try:
                f = z.open(name)
            except KeyError:
                continue
            nflows = 0
            try:
                for flow in ijson.items(f, "item"):
                    pkts = flow.get("x_packets", [])
                    if len(pkts) < DETAIL:
                        continue
                    proto_tcp, psrc, pdst = flow_meta(flow)
                    biflow_id = "%s|%s|%d" % (src, label, nflows)
                    use = pkts[: W * MAX_WIN_PER_FLOW]
                    for start in range(0, len(use), W):
                        win = use[start:start + W]
                        if len(win) < DETAIL:      # 末段不足 DETAIL 包则丢弃
                            break
                        feat = window_features(win)
                        feat["proto_tcp"] = proto_tcp
                        feat["port_src"] = psrc
                        feat["port_dst"] = pdst
                        feat["label"] = label
                        feat["biflow_id"] = biflow_id
                        feat["vpn"] = src
                        rows.append(feat)
                    nflows += 1
                    per_source_label_flows[(src, label)] += 1
                    if nflows >= K_FLOWS_PER_FILE:
                        break
            finally:
                f.close()
            print("  %-22s / %-13s : %d biflows" % (src, label, nflows), flush=True)
    z.close()
    return pd.DataFrame(rows)


def split_by_biflow(df, rng):
    """按 biflow 做 60/20/20 划分(同一流的窗口进同一份),逐类分层。"""
    df["split"] = "train"
    for label in LABELS:
        bids = sorted(df[df["label"] == label]["biflow_id"].unique().tolist())
        rng.shuffle(bids)
        n = len(bids)
        n_tr = int(round(0.6 * n)); n_ca = int(round(0.2 * n))
        train_b = set(bids[:n_tr]); calib_b = set(bids[n_tr:n_tr + n_ca]); test_b = set(bids[n_tr + n_ca:])
        for b, s in [(train_b, "train"), (calib_b, "calibration"), (test_b, "test")]:
            df.loc[df["biflow_id"].isin(b), "split"] = s
    return df


def balance_per_split(df, rng, cap_per_class_per_split):
    """每个 split 内把各类窗口下采样到不超过 cap(整窗口随机抽样,保持可复现)。"""
    keep_idx = []
    for s in ["train", "calibration", "test"]:
        for label in LABELS:
            idx = df[(df["split"] == s) & (df["label"] == label)].index.tolist()
            if len(idx) > cap_per_class_per_split:
                idx = rng.sample(idx, cap_per_class_per_split)
            keep_idx.extend(idx)
    return df.loc[sorted(keep_idx)].reset_index(drop=True)


FEATURE_MANIFEST = [
    # feature, p4_computable, stateful, note  (样本=一段 W=32 包窗口;明细只取前 DETAIL=8 包)
    ("proto_tcp", "YES", "no", "ipv4.protocol==6,解析即得"),
    ("port_src", "YES", "no", "tcp/udp 源端口(临时端口,信息量低)"),
    ("port_dst", "YES", "no", "tcp/udp 目的端口(VPN 隧道下反映隧道端口,非应用)"),
    ("len_1..len_8", "YES", "reg", "前8包长度=ipv4.totalLen;按流内包计数器索引(少量寄存器)"),
    ("dir_1..dir_8", "YES", "reg", "前8包方向:由入端口/流发起方判定(寄存器存发起方)"),
    ("iat_2..iat_8", "YES", "reg", "前8包相邻间隔=ingress_global_timestamp 差(寄存器存上一包时间戳)"),
    ("sum_len/min_len/max_len", "YES", "reg", "全段(32包)包长累加/最小/最大,整数运算(寄存器)"),
    ("n_fwd/n_bwd", "YES", "reg", "全段正向/反向包计数(寄存器)"),
    ("n_small/n_large", "YES", "reg", "全段 <200B 小包数 / >=1200B 近MTU大包数(比较+计数,寄存器)"),
    ("iat_sum/iat_max", "YES", "reg", "全段相邻间隔之和/最大(寄存器累加与比较)"),
    ("syn0/ack0/fin0/rst0/psh0", "YES", "no", "首包 TCP flags 位,解析即得"),
    ("(均值/方差等)", "NO", "-", "需除法/平方,P4 无除法 -> 本基线刻意不使用,改用 sum+count 等价表达"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap-per-class-per-split", type=int, default=1600)
    args = ap.parse_args()

    procdir = os.path.join(REPO, "data", "processed")
    os.makedirs(procdir, exist_ok=True)
    rng = random.Random(SEED)

    print("[extract] 流式读取 + 切窗口 ...")
    df = extract()
    print("[extract] 原始窗口样本数 = %d" % len(df))
    print("[extract] 各类窗口分布:%s" % dict(Counter(df["label"])))

    df = split_by_biflow(df, rng)
    df = balance_per_split(df, rng, args.cap_per_class_per_split)

    # 列顺序:特征在前,元数据在后
    meta_cols = ["label", "split", "biflow_id", "vpn"]
    feat_cols = [c for c in df.columns if c not in meta_cols]
    df = df[feat_cols + meta_cols]

    out = os.path.join(procdir, "features.csv")
    df.to_csv(out, index=False)
    print("[extract] 已写 %s (%d 行, %d 特征列)" % (out, len(df), len(feat_cols)))

    # calibration 单独存(只特征+标签,强调本步不使用)
    calib = df[df["split"] == "calibration"][feat_cols + ["label"]]
    calib.to_csv(os.path.join(procdir, "calibration.csv"), index=False)

    # 特征 P4 可实现性清单
    pd.DataFrame(FEATURE_MANIFEST,
                 columns=["feature", "p4_computable", "stateful", "note"]).to_csv(
        os.path.join(procdir, "feature_manifest.csv"), index=False)

    # 划分信息
    info = {
        "seed": SEED, "window_packets": W,
        "k_flows_per_file": K_FLOWS_PER_FILE, "max_win_per_flow": MAX_WIN_PER_FLOW,
        "cap_per_class_per_split": args.cap_per_class_per_split,
        "split_unit": "biflow (no biflow crosses splits)",
        "counts": {
            s: dict(Counter(df[df["split"] == s]["label"]))
            for s in ["train", "calibration", "test"]
        },
        "n_biflows_per_label": {
            lab: int(df[df["label"] == lab]["biflow_id"].nunique()) for lab in LABELS
        },
        "calibration_used_this_step": False,
    }
    with open(os.path.join(procdir, "split_info.json"), "w") as fh:
        json.dump(info, fh, indent=2, ensure_ascii=False)
    print("[extract] split counts: %s" % json.dumps(info["counts"], ensure_ascii=False))
    print("[extract] calibration 已单独存盘,本步不使用。")


if __name__ == "__main__":
    main()
