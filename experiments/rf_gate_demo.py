#!/usr/bin/env python3
"""
rf_gate_demo.py — CRISP-Net 第 7b 步编排:在网 RF+校准+τ 门控 与离线保形流水线 三级一致性验证

复用 7a 的完美哈希驱动(每流唯一 srcPort)与 feature_send.py。数据面每窗口经 Digest 上送
(flow_id, pred, score, calib8, accept);离线参考 = rf_pipeline.RFGatePipeline 在同一窗口特征向量上的
(pred, score, calib8, accept)。三级:L1 pred、L2 calib8、L3 accept。SEED=42。
"""
import os
import sys
import time
import argparse
import numpy as np
import pandas as pd

TUTORIALS_UTILS = os.path.expanduser("~/tutorials/utils")
sys.path.insert(0, TUTORIALS_UTILS)
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in ("topo", "control", "ml"):
    sys.path.insert(0, os.path.join(REPO, d))

from mininet.net import Mininet
from mininet.link import TCLink
from p4runtime_switch import P4RuntimeSwitch
from upload_topo import UploadTopo, configure_hosts
from rf_gate_controller import RFGateController
import extract_quic as EQ
import rf_pipeline as RP

BASE_PORT = 10000
W = 32
PARQUET = os.path.join(REPO, "data", "raw", "quic_pq", "datasets", "ucdavis-icdm19",
                       "preprocessed", "ucdavis-icdm19.parquet")
PROC = os.path.join(REPO, "data", "processed", "quic")
ZERO_COLS = {"proto_tcp", "port_src", "port_dst"}


def log(m): print("[7b] %s" % m, flush=True)


def feat_vec(sizes_w, dirbits_w, iat_us_w):
    lens = [int(x) for x in sizes_w]
    dirs = [1 if b == 1 else -1 for b in dirbits_w]
    rel = [0.0]
    for j in range(1, len(lens)):
        rel.append(rel[-1] + float(iat_us_w[j]) / 1000.0)
    wf = EQ.window_features(lens, dirs, rel)        # ms/±1
    vec = []
    for f in RP.FEATS:
        if f in RP.DIR_COLS:
            vec.append(1 if wf[f] == 1 else 0)
        elif f in RP.IAT_COLS:
            vec.append(int(round(wf[f] * 1000.0)))   # ms->µs
        elif f in ZERO_COLS:
            vec.append(0)
        else:
            vec.append(int(wf[f]))
    return vec


def build(max_flows, max_win):
    test_ids = set(pd.read_csv(os.path.join(PROC, "features.csv"))
                   .query("split=='test'")["biflow_id"].astype(str).unique())
    pq = pd.read_parquet(PARQUET, columns=["flow_id", "pkts_size", "pkts_dir", "pkts_iat"])
    flows = []; keys = []; vecs = []
    idx = 0
    for _, r in pq.iterrows():
        fid = str(r["flow_id"])
        if fid not in test_ids:
            continue
        size = np.asarray(r["pkts_size"]).astype(np.int64)
        pdir = np.asarray(r["pkts_dir"]).astype(np.int64)
        iat_s = np.asarray(r["pkts_iat"]).astype(float)
        n = min(len(size), len(pdir), len(iat_s)); k = min(max_win, n // W)
        if k == 0:
            continue
        m = k * W
        sizes = size[:m]; dirbits = (pdir[:m] == 1).astype(np.int64)
        iat_us = np.clip(np.round(iat_s[:m] * 1e6), 0, 60_000_000).astype(np.int64)
        srcport = BASE_PORT + idx
        flows.append((srcport, sizes, dirbits, iat_us))
        for w in range(k):
            sl = slice(w * W, (w + 1) * W)
            keys.append((srcport, w)); vecs.append(feat_vec(sizes[sl], dirbits[sl], iat_us[sl]))
        idx += 1
        if idx >= max_flows:
            break
    return flows, keys, np.array(vecs, dtype=np.int64)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True); ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--entries", default=os.path.join(PROC, "rf_entries.json"))
    ap.add_argument("--sw-path", default="simple_switch_grpc")
    ap.add_argument("--max-flows", type=int, default=60); ap.add_argument("--max-win", type=int, default=12)
    ap.add_argument("--logdir", default=os.path.join(REPO, "experiments", "logs"))
    args = ap.parse_args()
    os.makedirs(args.logdir, exist_ok=True)

    log("构造 spec + 离线参考(RFGatePipeline)...")
    P = RP.RFGatePipeline(PROC)
    flows, keys, vecs = build(args.max_flows, args.max_win)
    pred_ref, score_ref, calib_ref, accept_ref = P.reference(vecs)
    gt = {keys[i]: (int(pred_ref[i]), int(score_ref[i]), int(calib_ref[i]), int(accept_ref[i]))
          for i in range(len(keys))}
    log("选中 %d 流, %d 窗口;tau8=%d" % (len(flows), len(gt), int(P.tau8)))
    spec_path = os.path.join(PROC, "feature_drive_spec.npz")
    np.savez(spec_path, flows=np.array(flows, dtype=object))

    topo = UploadTopo(sw_path=args.sw_path, grpc_port=50051, thrift_port=9090,
                      log_file=os.path.join(args.logdir, "s1-rf.log"))
    net = Mininet(topo=topo, switch=P4RuntimeSwitch, link=TCLink, controller=None)
    rc = 1; ctrl = None
    try:
        net.start(); configure_hosts(net); net.get("s1").cmd("sleep 1")
        ctrl = RFGateController(args.p4info, args.bmv2_json, args.entries,
                                proto_dump_file=os.path.join(args.logdir, "s1-rf-p4rt.txt"))
        ctrl.install_pipeline()
        log("灌入 RF/LUT 表项 ...")
        n_ins = ctrl.install_entries(); ctrl.enable_digest(); ctrl.start_receiver()
        log("表项 %d 条已灌入(τ=%d 为编译常量),digest 使能" % (n_ins, int(P.tau8)))

        h1 = net.get("h1")
        out = h1.cmd("python3 %s --spec %s --iface h1-eth0"
                     % (os.path.join(REPO, "experiments", "feature_send.py"), spec_path))
        print(out.strip(), flush=True)

        prev = -1
        for _ in range(60):
            time.sleep(0.5); c = ctrl.count()
            if c == prev and c >= len(gt):
                break
            prev = c
        log("收到 digest %d / 期望 %d" % (ctrl.count(), len(gt)))

        with ctrl.lock:
            recs = list(ctrl.records)
        by_flow = {}
        for r in recs:
            by_flow.setdefault(r["flow_id"], []).append(r)

        L1 = L2 = L3 = Lsc = comp = miss = 0
        ex = []
        for (sp, w), (gp, gs, gc, ga) in gt.items():
            lst = by_flow.get(sp, [])
            if w >= len(lst):
                miss += 1; continue
            r = lst[w]; comp += 1
            if r["pred"] == gp: L1 += 1
            elif len(ex) < 12: ex.append(("L1", sp, w, r["pred"], gp))
            if r["score"] == gs: Lsc += 1
            elif len(ex) < 12: ex.append(("score", sp, w, r["score"], gs))
            if r["calib8"] == gc: L2 += 1
            elif len(ex) < 12: ex.append(("L2", sp, w, r["calib8"], gc))
            if r["accept"] == ga: L3 += 1
            elif len(ex) < 12: ex.append(("L3", sp, w, r["accept"], ga))

        log("==== 三级一致性(比对 %d 窗口,缺失 %d)====" % (comp, miss))
        log("  L1 在网RF预测 == sklearn:           %d/%d (%.4f)" % (L1, comp, L1 / max(comp, 1)))
        log("  (raw 软分数 score 一致:             %d/%d (%.4f))" % (Lsc, comp, Lsc / max(comp, 1)))
        log("  L2 在网校准分数 == 离线校准分数:     %d/%d (%.4f)" % (L2, comp, L2 / max(comp, 1)))
        log("  L3 在网 accept/defer == 离线保形判决: %d/%d (%.4f)  <-- 最关键" % (L3, comp, L3 / max(comp, 1)))
        if ex:
            log("不一致样例 (level, flow, win, innet, offline):")
            for e in ex:
                log("  %s" % (e,))
        ok = (comp >= 500 and miss == 0 and L1 == comp and L2 == comp and L3 == comp)
        log("==== 7b 三级一致性:%s ====" % ("PASS" if ok else "CHECK"))
        rc = 0 if ok else 2
    finally:
        if ctrl is not None:
            ctrl.stop_receiver(); ctrl.shutdown()
        net.stop(); log("Mininet 已停止")
    sys.exit(rc)


if __name__ == "__main__":
    main()
