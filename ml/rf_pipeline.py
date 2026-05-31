#!/usr/bin/env python3
"""
rf_pipeline.py — CRISP-Net 第 7b 步:P4 可实现的"单 RF10 硬投票 + isotonic 校准 + RCPS τ̂"参考流水线

为什么不是直接复用第 6 步的 CalibratedClassifierCV(cv=5):那是 5 个 RF10 + 5 个 isotonic 平均,
不是干净的"一棵 RF → 一个校准 LUT",难以忠实编进 P4。本步改用 **单 RF10 + 硬投票得票数** 作分数、
**单 isotonic LUT** 校准、并在 calibration 上**用第 6 步同一 RCPS 过程重标定 τ̂**(如实记录此偏离),
得到与数据面一一对应、可逐级验证的流水线。特征用**数据面单位**(dir∈{0,1},iat 整数微秒),与 7a 引擎一致。

本模块既是"离线参考"(给每样本算 pred/max_votes/8bit校准分/accept),也供 RF→P4 生成器导出表项。
SEED=42。
"""
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
from conformal import rcps_threshold   # 第6步同一 LTT/Clopper-Pearson 过程

SEED = 42
N_TREES = 10
ALPHA = 0.05
DELTA = 0.10

# 40 维特征顺序(features.csv 列序);8 个恒 0 列在 QUIC 下为 0
FEATS = ([f for i in range(1, 9) for f in ("len_%d" % i, "dir_%d" % i)] +
         ["iat_%d" % i for i in range(2, 9)] +
         ["sum_len", "min_len", "max_len", "n_fwd", "n_bwd", "n_small", "n_large",
          "iat_sum", "iat_max", "syn0", "ack0", "fin0", "rst0", "psh0",
          "proto_tcp", "port_src", "port_dst"])
IAT_COLS = ["iat_%d" % i for i in range(2, 9)] + ["iat_sum", "iat_max"]
DIR_COLS = ["dir_%d" % i for i in range(1, 9)]


def load_dataplane_features(proc):
    """读 features.csv 转成数据面单位:dir ±1->{1,0},iat ms->整数µs(round)。"""
    df = pd.read_csv(os.path.join(proc, "features.csv"))
    df = df.copy()
    for c in DIR_COLS:
        df[c] = (df[c].to_numpy() == 1).astype(np.int64)         # +1->1, -1->0
    for c in IAT_COLS:
        df[c] = np.round(df[c].to_numpy().astype(float) * 1000.0).astype(np.int64)  # ms->µs
    for c in FEATS:
        if c not in df:
            df[c] = 0
        df[c] = df[c].astype(np.int64)
    return df


PROBA_SCALE = 255            # 每棵树叶子的每类概率量化到 8-bit
SCORE_MAX = PROBA_SCALE * N_TREES   # 软分数上界 = 2550


def leaf_proba8(rf):
    """每棵树:leaf_id -> 8-bit 量化的每类概率(round(value/sum*255))。返回 list[ dict 或 array ]。"""
    tables = []
    for est in rf.estimators_:
        t = est.tree_
        val = t.value.reshape(t.value.shape[0], -1)   # [n_nodes, K] 计数
        tot = val.sum(1, keepdims=True); tot[tot == 0] = 1
        p8 = np.round(val / tot * PROBA_SCALE).astype(np.int64)  # [n_nodes,K]
        tables.append(p8)
    return tables


def soft_score(rf, X, p8_tables):
    """软投票(与 conformal.py 的 predict_proba 同义,定点化):各树叶子 8-bit 概率求和。
    返回 pred_idx(argmax,平票取低索引)、score(=max 累加,0..2550)、acc[N,K]。"""
    N = X.shape[0]; K = len(rf.classes_)
    acc = np.zeros((N, K), dtype=np.int64)
    for est, p8 in zip(rf.estimators_, p8_tables):
        leaf = est.apply(X)                  # 每样本叶子 id
        acc += p8[leaf]                      # [N,K] 累加该叶子的 8-bit 概率
    pred = acc.argmax(1)                      # 平票取最低索引
    score = acc[np.arange(N), pred]
    return pred, score, acc


class RFGatePipeline:
    def __init__(self, proc):
        self.df = load_dataplane_features(proc)
        self.tr = self.df[self.df.split == "train"]
        self.ca = self.df[self.df.split == "calibration"]
        self.te = self.df[self.df.split == "test"]
        self.classes = sorted(self.df["label"].unique().tolist())
        self.rf = RandomForestClassifier(n_estimators=N_TREES, max_depth=8,
                                         random_state=SEED, n_jobs=-1)
        self.rf.fit(self.tr[FEATS].to_numpy(), self.tr["label"].to_numpy())
        self.rf_classes = list(self.rf.classes_)
        self.p8 = leaf_proba8(self.rf)        # 各树 leaf->8bit 概率

        # isotonic:软分数(训练集,0..2550)-> P(判对);8-bit 校准 LUT(范围映射)
        ytr = self.tr["label"].to_numpy()
        pred_tr, sc_tr, _ = soft_score(self.rf, self.tr[FEATS].to_numpy(), self.p8)
        correct_tr = (np.array(self.rf_classes)[pred_tr] == ytr).astype(float)
        self.iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self.iso.fit(sc_tr.astype(float), correct_tr)
        # 预算每个可能 score 的 8-bit 校准值(LUT 索引 = score 0..2550)
        grid = np.arange(0, SCORE_MAX + 1)
        self.calib8 = np.round(self.iso.predict(grid.astype(float)) * 255).astype(np.int64)

        # 在 calibration 上 RCPS 标定 τ̂(8-bit 校准分数空间)
        pred_ca, sc_ca, _ = soft_score(self.rf, self.ca[FEATS].to_numpy(), self.p8)
        yca = self.ca["label"].to_numpy()
        correct_ca = (np.array(self.rf_classes)[pred_ca] == yca).astype(int)
        score_ca = self.calib8[sc_ca].astype(float)
        self.tau8 = rcps_threshold(score_ca, correct_ca, ALPHA, DELTA)

    def reference(self, X):
        """每样本离线参考:pred_idx, score(0..2550), calib8, accept。"""
        pred, sc, _ = soft_score(self.rf, X, self.p8)
        calib = self.calib8[sc]
        accept = (calib >= self.tau8).astype(int)
        return pred, sc, calib, accept


def main():
    proc = os.path.join(REPO, "data", "processed", "quic")
    P = RFGatePipeline(proc)
    print("classes:", P.rf_classes)
    print("tau8 =", P.tau8, " (calib8 distinct values:", sorted(set(P.calib8.tolist()))[:12], "...)")
    # 叶子总数(表项规模)
    leaves = [int((t.tree_.children_left == -1).sum()) for t in P.rf.estimators_]
    print("per-tree leaves:", leaves, "total:", sum(leaves))
    # test headline
    Xte = P.te[FEATS].to_numpy(); yte = P.te["label"].to_numpy()
    pred, mv, calib, accept = P.reference(Xte)
    predlab = np.array(P.rf_classes)[pred]
    acc = (predlab == yte).mean()
    correct = (predlab == yte).astype(int)
    cov = accept.mean()
    acc_err = (1 - correct[accept == 1]).mean() if accept.sum() else float("nan")
    from sklearn.metrics import f1_score
    print("hard-vote RF test acc=%.4f macroF1=%.4f" % (acc, f1_score(yte, predlab, average="macro")))
    print("α=5%% 运营点: cov(test)=%.3f accepted-err(test)=%.3f (对比第6步 ~0.50/~0.05)" % (cov, acc_err))


if __name__ == "__main__":
    main()
