#!/usr/bin/env python3
"""
rf_gate_cl_demo.py — CRISP-Net 第 7c 步 Part B:上交闭环 + 端到端复现

数据面每窗口:RF+门控决策(dec digest 永远上送);defer 时额外把 32 包序列(seq digest)上送 host。
host:accept 窗口用在网 RF 预测;defer 窗口用 host DNN(对上送序列)预测。按 flow_id 聚合,与真值比对。
报覆盖率/端到端精度/接受集错误率、上送量节省、延迟量级。用 Part A 修正 τ̂₈=241。SEED=42。
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
from rf_gate_cl_controller import RFGateCLController
import rf_pipeline as RP
from host_dnn import HostDNN

BASE_PORT = 10000; W = 32
PARQUET = os.path.join(REPO, "data", "raw", "quic_pq", "datasets", "ucdavis-icdm19",
                       "preprocessed", "ucdavis-icdm19.parquet")
PROC = os.path.join(REPO, "data", "processed", "quic")


def log(m): print("[7c] %s" % m, flush=True)


def build(max_flows, max_win):
    test_ids = set(pd.read_csv(os.path.join(PROC, "features.csv"))
                   .query("split=='test'")["biflow_id"].astype(str).unique())
    pq = pd.read_parquet(PARQUET, columns=["flow_id", "app", "pkts_size", "pkts_dir", "pkts_iat"])
    flows = []; label = {}; idx = 0
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
        srcport = BASE_PORT + idx
        flows.append((srcport, size[:m], (pdir[:m] == 1).astype(np.int64),
                      np.clip(np.round(iat_s[:m] * 1e6), 0, 60_000_000).astype(np.int64)))
        label[srcport] = str(r["app"])
        idx += 1
        if idx >= max_flows:
            break
    return flows, label


def seq_to_X(rec):
    X = np.zeros((W, 8), dtype=np.float32)
    for i in range(1, W + 1):
        sl = rec["slen_%d" % i]; sd = rec["sdir_%d" % i]; si = rec["siat_%d" % i]
        sign = 1.0 if sd == 1 else -1.0
        X[i - 1, 0] = sl * sign; X[i - 1, 1] = si / 1000.0; X[i - 1, 2] = sign
    return X


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True); ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--entries", default=os.path.join(PROC, "rf_entries_cl.json"))
    ap.add_argument("--sw-path", default="simple_switch_grpc")
    ap.add_argument("--max-flows", type=int, default=80); ap.add_argument("--max-win", type=int, default=12)
    ap.add_argument("--logdir", default=os.path.join(REPO, "experiments", "logs"))
    args = ap.parse_args()
    os.makedirs(args.logdir, exist_ok=True)

    P = RP.RFGatePipeline(PROC)
    log("host DNN 训练中 ...")
    hd = HostDNN(PROC)
    import json as _json
    tau_used = _json.load(open(args.entries))["tau8"]
    flows, flabel = build(args.max_flows, args.max_win)
    nwin = sum(len(f[1]) // W for f in flows)
    log("选中 %d 流, %d 窗口;τ̂₈=%d(Part A 修正)" % (len(flows), nwin, int(tau_used)))
    spec = os.path.join(PROC, "feature_drive_spec.npz")
    np.savez(spec, flows=np.array(flows, dtype=object))

    topo = UploadTopo(sw_path=args.sw_path, grpc_port=50051, thrift_port=9090,
                      log_file=os.path.join(args.logdir, "s1-cl.log"))
    net = Mininet(topo=topo, switch=P4RuntimeSwitch, link=TCLink, controller=None)
    rc = 1; ctrl = None
    try:
        net.start(); configure_hosts(net); net.get("s1").cmd("sleep 1")
        ctrl = RFGateCLController(args.p4info, args.bmv2_json, args.entries,
                                  proto_dump_file=os.path.join(args.logdir, "s1-cl-p4rt.txt"))
        ctrl.install_pipeline(); n = ctrl.install_entries(); ctrl.enable_digests(); ctrl.start_receiver()
        log("表项 %d 灌入,两类 digest 使能" % n)
        h1 = net.get("h1")
        t0 = time.time()
        out = h1.cmd("python3 %s --spec %s --iface h1-eth0 --win 32 --gap 0.01"
                     % (os.path.join(REPO, "experiments", "feature_send.py"), spec))
        print(out.strip(), flush=True)
        prev = -1
        for _ in range(120):
            time.sleep(0.5); d, s = ctrl.counts()
            if (d + s) == prev and (d + s) >= nwin:
                break
            prev = d + s
        d, s = ctrl.counts()
        log("收到 digest 合计 %d / 期望窗口 %d(dec/accept=%d, seq/defer=%d)" % (d + s, nwin, d, s))

        with ctrl.lock:
            dec = list(ctrl.dec); seq = list(ctrl.seq)
        # 每窗口恰一条 digest:dec=accept(在网RF判),seq=defer(上送序列->host DNN)。
        # 同一流所有窗口真值相同(=该流 app),故无需窗口序对齐。
        n_acc = len(dec); n_def = len(seq); tot = n_acc + n_def
        # accept 集:在网 RF 预测
        acc_correct = acc_err_n = 0
        for r in dec:
            pred = P.rf_classes[r["pred"]]; truth = flabel[r["flow_id"]]
            if pred == truth:
                acc_correct += 1
            else:
                acc_err_n += 1
        # defer 集:host DNN 对上送序列预测
        defX = [seq_to_X(r) for r in seq]
        dnn_pred = hd.predict(np.array(defX)) if defX else np.array([])
        def_correct = sum(1 for i, r in enumerate(seq) if dnn_pred[i] == flabel[r["flow_id"]])
        correct = acc_correct + def_correct
        cov = n_acc / tot; e2e = correct / tot; aerr = acc_err_n / max(n_acc, 1)
        log("==== Part B 端到端(实测,%d 窗口)====" % tot)
        log("  覆盖率 φ(在网接受比例) = %.3f" % cov)
        log("  接受集错误率           = %.3f  (≤α=0.05 ?)" % aerr)
        log("  端到端精度             = %.3f  (accept→在网RF / defer→host DNN)" % e2e)
        log("  纯在网RF基线 / 纯DNN基线 见第5步(0.779 / 0.819)")
        # 上送量节省:重序列(32包)仅 defer 上送;accept 仅轻量决策标记
        savings = 1.0 - (n_def / tot)
        log("  上送量:仅 defer 上送 %d/%d 窗口的32包序列(accept 不送重序列)-> 相比全上送省 %.1f%%(=覆盖率)"
            % (n_def, tot, 100 * savings))
        ok = (tot >= 500 and tot == nwin and aerr <= 0.05)
        log("==== 7c Part B:%s ====" % ("PASS" if ok else "CHECK"))
        rc = 0 if ok else 2
    finally:
        if ctrl is not None:
            ctrl.stop_receiver(); ctrl.shutdown()
        net.stop(); log("Mininet 已停止")
    sys.exit(rc)


if __name__ == "__main__":
    main()
