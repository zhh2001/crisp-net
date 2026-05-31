#!/usr/bin/env python3
"""
feature_engine_demo.py — CRISP-Net 第 7a 步编排:在网特征 == 离线特征 一致性验证

1) 从 QUIC parquet 选取**测试集**流(features.csv split==test 的 flow_id),取前 k*32 包(整窗口),
   每流分配唯一 srcPort;为每包携带 dir(0/1) 与 iat_us(整数µs,clip 6e7),包长合成为真实 pkts_size。
2) Ground truth:对每个窗口用 **extract_quic.window_features**(即生成 features.csv 的同一函数)算离线特征,
   iat 走携带的 µs/1000 ms(故与在网逐位对应)。
3) 起 1sw2host 拓扑 + FeatureController(收 digest);h1 发包;digest 落控制器。
4) 按 (flow_id, 窗口序) 把在网 digest 与离线 GT **逐特征**比对;报一致率/最大误差;不一致查根因。

复用第 2/5 步经验。calibration 不涉及。SEED=42。
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
sys.path.insert(0, os.path.join(REPO, "topo"))
sys.path.insert(0, os.path.join(REPO, "control"))
sys.path.insert(0, os.path.join(REPO, "ml"))

from mininet.net import Mininet
from mininet.link import TCLink
from p4runtime_switch import P4RuntimeSwitch
from upload_topo import UploadTopo, configure_hosts
from feature_controller import FeatureController
import extract_quic as EQ   # window_features / 常量,与 features.csv 同源

SEED = 42
BASE_PORT = 10000
NUM_FLOWS = 256
W = 32
PARQUET = os.path.join(REPO, "data", "raw", "quic_pq", "datasets", "ucdavis-icdm19",
                       "preprocessed", "ucdavis-icdm19.parquet")
PROC = os.path.join(REPO, "data", "processed", "quic")
INT_FEATS = (["len_%d" % i for i in range(1, 9)] +
             ["sum_len", "min_len", "max_len", "n_fwd", "n_bwd", "n_small", "n_large"])
IAT_FEATS = ["iat_%d" % i for i in range(2, 9)] + ["iat_sum", "iat_max"]
DIR_FEATS = ["dir_%d" % i for i in range(1, 9)]


def log(m): print("[7a] %s" % m, flush=True)


def build_specs_and_gt(max_flows, max_win):
    """返回 flows(发送 spec)与 gt(按 (srcport,win) -> 离线特征 dict)。"""
    test_ids = set(pd.read_csv(os.path.join(PROC, "features.csv"))
                   .query("split=='test'")["biflow_id"].astype(str).unique())
    pq = pd.read_parquet(PARQUET, columns=["flow_id", "pkts_size", "pkts_dir", "pkts_iat"])
    flows = []
    gt = {}
    idx = 0
    for _, r in pq.iterrows():
        fid = str(r["flow_id"])
        if fid not in test_ids:
            continue
        size = np.asarray(r["pkts_size"]).astype(np.int64)
        pdir = np.asarray(r["pkts_dir"]).astype(np.int64)
        iat_s = np.asarray(r["pkts_iat"]).astype(float)
        n = min(len(size), len(pdir), len(iat_s))
        k = min(max_win, n // W)               # 整窗口数
        if k == 0:
            continue
        m = k * W
        sizes = size[:m]
        dirbits = (pdir[:m] == 1).astype(np.int64)               # 1=fwd,0=bwd(与 extract_quic 同义)
        iat_us = np.clip(np.round(iat_s[:m] * 1e6), 0, 60_000_000).astype(np.int64)
        srcport = BASE_PORT + idx
        flows.append((srcport, sizes, dirbits, iat_us))
        # ground truth(逐窗口,用生成 features.csv 的同一函数)
        for w in range(k):
            sl = slice(w * W, (w + 1) * W)
            lens = [int(x) for x in sizes[sl]]
            dirs = [1 if b == 1 else -1 for b in dirbits[sl]]    # ±1
            iu = iat_us[sl]
            rel = [0.0]
            for j in range(1, len(lens)):
                rel.append(rel[-1] + float(iu[j]) / 1000.0)      # ms(=携带µs/1000)
            feat = EQ.window_features(lens, dirs, rel)
            gt[(srcport, w)] = feat
        idx += 1
        if idx >= max_flows:
            break
    return flows, gt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True)
    ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--sw-path", default="simple_switch_grpc")
    ap.add_argument("--max-flows", type=int, default=60)
    ap.add_argument("--max-win", type=int, default=12)
    ap.add_argument("--logdir", default=os.path.join(REPO, "experiments", "logs"))
    args = ap.parse_args()
    os.makedirs(args.logdir, exist_ok=True)

    log("构造发送 spec + 离线 ground truth ...")
    flows, gt = build_specs_and_gt(args.max_flows, args.max_win)
    n_windows = len(gt)
    log("选中 %d 条测试流,共 %d 个整窗口(W=32)" % (len(flows), n_windows))
    spec_path = os.path.join(PROC, "feature_drive_spec.npz")
    np.savez(spec_path, flows=np.array(flows, dtype=object))

    topo = UploadTopo(sw_path=args.sw_path, grpc_port=50051, thrift_port=9090,
                      log_file=os.path.join(args.logdir, "s1-feat.log"))
    net = Mininet(topo=topo, switch=P4RuntimeSwitch, link=TCLink, controller=None)
    rc = 1
    ctrl = None
    try:
        net.start(); configure_hosts(net); net.get("s1").cmd("sleep 1")
        ctrl = FeatureController(args.p4info, args.bmv2_json, address="127.0.0.1:50051",
                                 proto_dump_file=os.path.join(args.logdir, "s1-feat-p4rt.txt"))
        ctrl.install_pipeline(); ctrl.enable_digest(); ctrl.start_receiver()
        log("pipeline + digest 就绪;开始从 h1 发包 ...")

        h1 = net.get("h1")
        sender = os.path.join(REPO, "experiments", "feature_send.py")
        out = h1.cmd("python3 %s --spec %s --iface h1-eth0" % (sender, spec_path))
        print(out.strip(), flush=True)

        # 等 digest 收完
        prev = -1
        for _ in range(40):
            time.sleep(0.5)
            c = ctrl.count()
            if c == prev and c >= n_windows:
                break
            prev = c
        log("收到 digest 数 = %d / 期望窗口 = %d" % (ctrl.count(), n_windows))

        # ---- 按 (flow_id, 窗口序) 对齐 ----
        with ctrl.lock:
            recs = list(ctrl.records)
        by_flow = {}
        for r in recs:
            by_flow.setdefault(r["flow_id"], []).append(r)

        # 逐特征比对
        int_ok = {f: 0 for f in INT_FEATS}; int_tot = {f: 0 for f in INT_FEATS}
        dir_ok = {f: 0 for f in DIR_FEATS}; dir_tot = {f: 0 for f in DIR_FEATS}
        iat_maxerr = {f: 0.0 for f in IAT_FEATS}; iat_tot = {f: 0 for f in IAT_FEATS}
        compared = 0; missing = 0; mism_examples = []
        for (srcport, w), feat in gt.items():
            lst = by_flow.get(srcport, [])
            if w >= len(lst):
                missing += 1; continue
            r = lst[w]; compared += 1
            for f in INT_FEATS:
                int_tot[f] += 1
                if int(r[f]) == int(feat[f]):
                    int_ok[f] += 1
                elif len(mism_examples) < 12:
                    mism_examples.append((srcport, w, f, int(r[f]), int(feat[f])))
            for f in DIR_FEATS:
                dir_tot[f] += 1
                innet = 1 if r[f] == 1 else -1     # digest dir bit 0/1 -> ±1
                if innet == int(feat[f]):
                    dir_ok[f] += 1
                elif len(mism_examples) < 12:
                    mism_examples.append((srcport, w, f, innet, int(feat[f])))
            for f in IAT_FEATS:
                iat_tot[f] += 1
                innet_ms = r[f] / 1000.0           # digest µs -> ms
                iat_maxerr[f] = max(iat_maxerr[f], abs(innet_ms - float(feat[f])))

        # ---- 报告 ----
        log("==== 一致性结果(比对窗口数 %d,缺失 %d)====" % (compared, missing))
        all_int_exact = all(int_ok[f] == int_tot[f] for f in INT_FEATS) and \
                        all(dir_ok[f] == dir_tot[f] for f in DIR_FEATS)
        n_int_fields = len(INT_FEATS) + len(DIR_FEATS)
        int_exact_fields = sum(int_ok[f] == int_tot[f] for f in INT_FEATS) + \
                           sum(dir_ok[f] == dir_tot[f] for f in DIR_FEATS)
        log("整数/方向特征(%d 个):完全一致字段 %d/%d" % (n_int_fields, int_exact_fields, n_int_fields))
        for f in INT_FEATS:
            if int_ok[f] != int_tot[f]:
                log("  不一致 %s: %d/%d" % (f, int_ok[f], int_tot[f]))
        for f in DIR_FEATS:
            if dir_ok[f] != dir_tot[f]:
                log("  不一致 %s: %d/%d" % (f, dir_ok[f], dir_tot[f]))
        max_iat_err = max(iat_maxerr.values()) if iat_maxerr else 0
        log("IAT 特征(%d 个,µs->ms 后比 features.csv 生成器):最大绝对误差 = %.6g ms" %
            (len(IAT_FEATS), max_iat_err))
        if mism_examples:
            log("不一致样例(flow,win,feat,innet,offline):")
            for e in mism_examples:
                log("  %s" % (e,))

        ok = all_int_exact and (max_iat_err < 1e-6) and compared >= 500 and missing == 0
        # collisions
        try:
            cid = ctrl.helper.get_counters_id  # noqa
        except Exception:
            pass
        log("==== 7a 一致性:%s ====" % ("PASS" if ok else "CHECK"))
        rc = 0 if ok else 2
    finally:
        if ctrl is not None:
            ctrl.stop_receiver(); ctrl.shutdown()
        net.stop()
        log("Mininet 已停止")
    sys.exit(rc)


if __name__ == "__main__":
    main()
