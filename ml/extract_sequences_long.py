#!/usr/bin/env python3
"""
extract_sequences_long.py — CRISP-Net 第3步「更多包」变体:每条 biflow 取前 L 包逐包序列。

用于论证"上交时多送些包能让专家更强"。**复用第2步同一 biflow 划分**(读 biflow_split.json),
一条 biflow 一个样本(而非窗口)。calibration biflow 不纳入(只读不用)。
"""
import os
import json
import argparse
import zipfile
import numpy as np

import ijson

from extract_features import (ZIP, ROOT, SOURCES, LABELS, DETAIL, K_FLOWS_PER_FILE,
                              IAT_CLIP_MS, SEQ_CHANNELS, parse_ts, tcp_flag_bits, flow_meta)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(REPO, "data", "processed")


def build_seq(pkts, L):
    arr = np.zeros((L, len(SEQ_CHANNELS)), dtype=np.float32)
    prev = None
    for i, p in enumerate(pkts[:L]):
        try:
            b = int(p["bytes"])
        except Exception:
            b = 0
        ts = parse_ts(p.get("timestamp_start", ""))
        iat = min(max((ts - prev) * 1000.0, 0.0), IAT_CLIP_MS) if (prev is not None and ts is not None) else 0.0
        if ts is not None:
            prev = ts
        fb = tcp_flag_bits(p.get("tcp_flags", ""))
        arr[i, 0] = float(b); arr[i, 1] = float(iat)
        arr[i, 2] = 1.0 if b > 0 else (-1.0 if b < 0 else 0.0)
        arr[i, 3] = fb["syn"]; arr[i, 4] = fb["ack"]; arr[i, 5] = fb["fin"]
        arr[i, 6] = fb["rst"]; arr[i, 7] = fb["psh"]
    return arr, min(len(pkts), L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--L", type=int, default=128)
    args = ap.parse_args()
    L = args.L

    bmap = json.load(open(os.path.join(PROC, "biflow_split.json")))
    X, seqlen, scal, split, label, bids = [], [], [], [], [], []
    z = zipfile.ZipFile(ZIP)
    for lab in LABELS:
        for src in SOURCES:
            name = "%s/%s/%s.json" % (ROOT, src, lab)
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
                    bid = "%s|%s|%d" % (src, lab, nflows)
                    nflows += 1
                    if bid not in bmap:
                        if nflows >= K_FLOWS_PER_FILE:
                            break
                        continue
                    sp = bmap[bid]["split"]
                    if sp == "calibration":     # 只读不用,跳过
                        if nflows >= K_FLOWS_PER_FILE:
                            break
                        continue
                    proto_tcp, psrc, pdst = flow_meta(flow)
                    sarr, slen = build_seq(pkts, L)
                    X.append(sarr); seqlen.append(slen)
                    scal.append([proto_tcp, min(pdst, 65535) / 65535.0])
                    split.append(sp); label.append(lab); bids.append(bid)
                    if nflows >= K_FLOWS_PER_FILE:
                        break
            finally:
                f.close()
    z.close()
    X = np.asarray(X, dtype=np.float32)
    out = os.path.join(PROC, "sequences_long_%d.npz" % L)
    np.savez_compressed(out, X_seq=X, seq_len=np.asarray(seqlen, np.int16),
                        scalars=np.asarray(scal, np.float32),
                        split=np.asarray(split), label=np.asarray(label),
                        biflow_id=np.asarray(bids), channels=np.array(SEQ_CHANNELS))
    from collections import Counter
    print("[long] L=%d  样本(biflow)=%d  shape=%s" % (L, len(X), X.shape))
    print("[long] split分布:", Counter(split))
    print("[long] 已写 %s" % out)


if __name__ == "__main__":
    main()
