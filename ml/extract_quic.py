#!/usr/bin/env python3
"""
extract_quic.py — CRISP-Net 第 5 步:UC Davis QUIC 数据集特征提取(与 VPN 严格同口径)

数据集:UC Davis QUIC (Rezaei/ICDM19),tcbench 预处理为 parquet(figshare 23538141)。
5 个 Google 服务:google-search/google-drive/google-doc/youtube/google-music,共 6672 条流。
每条流含逐包数组:pkts_size(包长,正)、pkts_dir(方向,0/1)、pkts_iat(相邻间隔,秒)。

与第 2 步**完全相同**的 40 维数据平面可算特征 schema 与 W=32 窗口切法,保证跨数据集可比:
  前 8 包逐包 len/dir/iat + 全段 sum/min/max/n_fwd/n_bwd/n_small/n_large/iat_sum/iat_max
  + proto_tcp/port_src/port_dst + 首包 TCP flags。
QUIC=UDP 且该格式无端口/无 TCP flags → proto_tcp=0、port_*=0、flags=0(如实置常数);
真正的信号(包长/方向/时间)与 VPN 同定义。窗口内 IAT 用 pkts_iat 重建局部相对时间,
逐包间隔计算与 VPN(rel[k]-rel[k-1])完全一致。

按流 60/20/20 划分(每条流=一个 flow_id,无泄漏),calibration 预留不用,SEED=42。
输出到 data/processed/quic/(不覆盖 VPN 产物)。
"""
import os
import json
import glob
import random
import argparse
from collections import Counter
import numpy as np
import pandas as pd

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARQUET = os.path.join(REPO, "data", "raw", "quic_pq", "datasets", "ucdavis-icdm19",
                       "preprocessed", "ucdavis-icdm19.parquet")
OUTDIR = os.path.join(REPO, "data", "processed", "quic")

# —— 与 VPN 同口径常量 ——
W = 32
DETAIL = 8
SMALL_TH = 200
LARGE_TH = 1200
MAX_WIN_PER_FLOW = 12
IAT_CLIP_MS = 60000.0
SEQ_CHANNELS = ["signed_len", "iat_ms", "dir", "syn", "ack", "fin", "rst", "psh"]


def window_features(lens, dirs, rel):
    """与 extract_features.window_features 完全一致(QUIC 无 flags -> 0)。rel: 窗口内局部相对时间(ms)。"""
    feat = {}
    for k in range(DETAIL):
        feat["len_%d" % (k + 1)] = lens[k]
        feat["dir_%d" % (k + 1)] = dirs[k]
    for k in range(1, DETAIL):
        d = rel[k] - rel[k - 1]
        feat["iat_%d" % (k + 1)] = float(min(max(d, 0.0), IAT_CLIP_MS))
    feat["sum_len"] = int(sum(lens)); feat["min_len"] = int(min(lens)); feat["max_len"] = int(max(lens))
    feat["n_fwd"] = int(sum(1 for d in dirs if d > 0))
    feat["n_bwd"] = int(sum(1 for d in dirs if d < 0))
    feat["n_small"] = int(sum(1 for x in lens if x < SMALL_TH))
    feat["n_large"] = int(sum(1 for x in lens if x >= LARGE_TH))
    iats = [min(max(rel[k] - rel[k - 1], 0.0), IAT_CLIP_MS) for k in range(1, len(rel))]
    feat["iat_sum"] = float(sum(iats)) if iats else 0.0
    feat["iat_max"] = float(max(iats)) if iats else 0.0
    feat["syn0"] = 0; feat["ack0"] = 0; feat["fin0"] = 0; feat["rst0"] = 0; feat["psh0"] = 0
    return feat


def window_sequence(lens, dirs, rel):
    arr = np.zeros((W, len(SEQ_CHANNELS)), dtype=np.float32)
    for i in range(min(len(lens), W)):
        iat = (rel[i] - rel[i - 1]) if i > 0 else 0.0
        arr[i, 0] = float(lens[i]) * (dirs[i] if dirs[i] != 0 else 1)
        arr[i, 1] = float(min(max(iat, 0.0), IAT_CLIP_MS))
        arr[i, 2] = float(dirs[i])
    return arr, min(len(lens), W)


def extract():
    df = pd.read_parquet(PARQUET, columns=["app", "flow_id", "pkts_size", "pkts_dir", "pkts_iat"])
    rows, seqs, seqlens = [], [], []
    per_class = Counter()
    N = W * MAX_WIN_PER_FLOW
    for _, r in df.iterrows():
        lab = str(r["app"])
        size = np.asarray(r["pkts_size"])[:N]
        pdir = np.asarray(r["pkts_dir"])[:N]
        iat_ms = np.asarray(r["pkts_iat"])[:N] * 1000.0          # 秒 -> 毫秒
        n = min(len(size), len(pdir), len(iat_ms))
        if n < DETAIL:
            continue
        lens = [abs(int(x)) for x in size[:n]]
        dirs = [1 if int(d) == 1 else -1 for d in pdir[:n]]      # 1->+1, 0->-1
        fid = str(r["flow_id"])
        per_class[lab] += 1
        for start in range(0, n, W):
            wl = lens[start:start + W]
            if len(wl) < DETAIL:
                break
            wd = dirs[start:start + W]
            # 重建窗口内局部相对时间(ms):rel[0]=0,rel[j]=rel[j-1]+iat(全局 start+j)
            seg_iat = iat_ms[start:start + len(wl)]
            rel = [0.0]
            for j in range(1, len(wl)):
                rel.append(rel[-1] + float(seg_iat[j]))          # seg_iat[j] = 全局第 start+j 包相对前一包的间隔
            feat = window_features(wl, wd, rel)
            feat["proto_tcp"] = 0; feat["port_src"] = 0; feat["port_dst"] = 0
            feat["label"] = lab; feat["biflow_id"] = fid; feat["vpn"] = "quic"
            rows.append(feat)
            sa, sl = window_sequence(wl, wd, rel)
            seqs.append(sa); seqlens.append(sl)
    return pd.DataFrame(rows), np.asarray(seqs, np.float32), np.asarray(seqlens, np.int16), per_class


def split_by_flow(df, rng, labels):
    df["split"] = "train"
    for lab in labels:
        bids = sorted(df[df["label"] == lab]["biflow_id"].unique().tolist())
        rng.shuffle(bids)
        n = len(bids); n_tr = int(round(0.6 * n)); n_ca = int(round(0.2 * n))
        for s, name in [(set(bids[:n_tr]), "train"), (set(bids[n_tr:n_tr + n_ca]), "calibration"),
                        (set(bids[n_tr + n_ca:]), "test")]:
            df.loc[df["biflow_id"].isin(s), "split"] = name
    return df


def balance(df, seqs, seqlens, rng, cap, labels):
    keep = []
    for s in ["train", "calibration", "test"]:
        for lab in labels:
            idx = df[(df["split"] == s) & (df["label"] == lab)].index.tolist()
            if len(idx) > cap:
                idx = rng.sample(idx, cap)
            keep.extend(idx)
    keep = sorted(keep)
    return df.loc[keep].reset_index(drop=True), seqs[keep], seqlens[keep]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap-per-class-per-split", type=int, default=1600)
    args = ap.parse_args()
    os.makedirs(OUTDIR, exist_ok=True)
    rng = random.Random(SEED)

    print("[quic] 读 parquet + 切窗口 ...")
    df, seqs, seqlens, per_class = extract()
    print("[quic] 每类流数:", dict(per_class))
    print("[quic] 原始窗口样本数 =", len(df))
    labels = sorted(df["label"].unique().tolist())
    df = split_by_flow(df, rng, labels)
    df, seqs, seqlens = balance(df, seqs, seqlens, rng, args.cap_per_class_per_split, labels)

    meta = ["label", "split", "biflow_id", "vpn"]
    feat_cols = [c for c in df.columns if c not in meta]
    df = df[feat_cols + meta]
    df.to_csv(os.path.join(OUTDIR, "features.csv"), index=False)
    np.savez_compressed(os.path.join(OUTDIR, "sequences.npz"), X_seq=seqs, seq_len=seqlens,
                        channels=np.array(SEQ_CHANNELS),
                        split=df["split"].to_numpy(), label=df["label"].to_numpy())
    df[df.split == "calibration"][feat_cols + ["label"]].to_csv(
        os.path.join(OUTDIR, "calibration.csv"), index=False)
    info = {"seed": SEED, "window_packets": W, "dataset": "UC Davis QUIC ICDM19 (figshare 23538141, tcbench parquet)",
            "cap_per_class_per_split": args.cap_per_class_per_split,
            "n_flows_per_label": {l: int(df[df.label == l]["biflow_id"].nunique()) for l in labels},
            "counts": {s: dict(Counter(df[df.split == s]["label"])) for s in ["train", "calibration", "test"]},
            "calibration_used_this_step": False,
            "note": "QUIC=UDP,无 ports/TCP flags -> proto_tcp/port_*/flags 恒为0;其余特征与VPN同定义/同W=32"}
    json.dump(info, open(os.path.join(OUTDIR, "split_info.json"), "w"), indent=2, ensure_ascii=False)
    print("[quic] features.csv 行=%d 特征列=%d  X_seq=%s" % (len(df), len(feat_cols), seqs.shape))
    print("[quic] split:", json.dumps(info["counts"], ensure_ascii=False))
    print("[quic] 每类 flow 数:", info["n_flows_per_label"])


if __name__ == "__main__":
    main()
