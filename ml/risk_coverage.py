#!/usr/bin/env python3
"""
risk_coverage.py — CRISP-Net 第 3 步:专家增益量化(B) + 选择性 risk-coverage 分析(C)

门控思路:廉价 RF 在网判,**RF 得票比例**作门控分数;高分(自信)的流由 RF 直接判(在网接受),
低分(不确定)的流上交 host DNN 专家判。扫阈值 τ 得 risk-coverage 曲线与运营点。

依赖:features.csv(同第2步划分,retrain DT/RF)、preds_test_dnn.csv(DNN 专家,dnn_expert.py 产出)。
**不读取 calibration 份**;概率校准用 train 上的交叉验证(CalibratedClassifierCV),不碰 calibration。
固定 SEED=42。所有数字在 test 集上。
"""
import os
import json
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, f1_score, recall_score, confusion_matrix

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(REPO, "data", "processed")
FIG = os.path.join(REPO, "experiments", "figures")
LABELS = ["mail", "meet", "non_streaming", "ssh", "streaming"]
AMBIG = ["streaming", "non_streaming", "meet"]
NON_FEATURE = {"label", "split", "biflow_id", "vpn"}
out = []


def log(s=""):
    print(s); out.append(s)


def load():
    df = pd.read_csv(os.path.join(PROC, "features.csv"))
    fc = [c for c in df.columns if c not in NON_FEATURE]
    tr, te = df[df.split == "train"], df[df.split == "test"]
    return df, fc, tr, te


def cheap_model_scores(tr, te, fc, model):
    model.fit(tr[fc].values, tr["label"].values)
    proba = model.predict_proba(te[fc].values)
    classes = list(model.classes_)
    pred = model.classes_[proba.argmax(1)]
    conf = proba.max(1)
    return pred, conf, proba, classes


def selective_curve(conf, correct_cheap, correct_dnn, n_grid=200):
    """按 conf 降序接受;返回 (coverage, accepted_acc, e2e_acc)。
    accepted 用 cheap 判,rejected 用 DNN 判。"""
    order = np.argsort(-conf)
    cc = correct_cheap[order].astype(float)
    cd = correct_dnn[order].astype(float)
    N = len(conf)
    cum_cheap = np.cumsum(cc)                  # 接受集里 cheap 判对数
    tot_dnn = cd.sum()
    cum_dnn_rejected = tot_dnn - np.cumsum(cd)  # 被拒绝(其余)里 DNN 判对数
    cov, acc_acc, e2e = [], [], []
    ks = np.unique(np.linspace(1, N, n_grid).astype(int))
    for k in ks:
        cov.append(k / N)
        acc_acc.append(cum_cheap[k - 1] / k)
        e2e.append((cum_cheap[k - 1] + cum_dnn_rejected[k - 1]) / N)
    return np.array(cov), np.array(acc_acc), np.array(e2e)


def max_coverage_at_alpha(conf, correct_cheap, alpha):
    """接受集错误率 ≤ alpha 时,最大覆盖率与对应 conf 阈值。"""
    order = np.argsort(-conf)
    cc = correct_cheap[order].astype(float)
    cum = np.cumsum(cc)
    N = len(conf)
    best_k = 0
    for k in range(1, N + 1):
        err = 1.0 - cum[k - 1] / k
        if err <= alpha:
            best_k = k
    if best_k == 0:
        return 0.0, 1.01, None
    thr = conf[order][best_k - 1]
    return best_k / N, thr, best_k


def coverage_at_conf(conf, thr):
    return float((conf >= thr).mean())


def main():
    os.makedirs(FIG, exist_ok=True)
    df, fc, tr, te = load()
    ytrue = te["label"].values

    # ---- DNN 专家预测(对齐 test 行顺序)----
    dnn = pd.read_csv(os.path.join(PROC, "preds_test_dnn.csv"))
    assert len(dnn) == len(te), "DNN 预测行数与 test 不符"
    assert (dnn["true_label"].values == ytrue).all(), "DNN 与 features test 标签未对齐"
    dnn_pred = dnn["pred_label"].values
    correct_dnn = (dnn_pred == ytrue)

    # ---- 廉价模型:DT / RF10 / RF100 ----
    dt = DecisionTreeClassifier(max_depth=10, random_state=SEED)
    rf10 = RandomForestClassifier(n_estimators=10, max_depth=8, random_state=SEED, n_jobs=-1)
    rf100 = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=SEED, n_jobs=-1)
    dt_pred, dt_conf, _, _ = cheap_model_scores(tr, te, fc, dt)
    rf_pred, rf_conf, _, _ = cheap_model_scores(tr, te, fc, rf10)
    rf100_pred, rf100_conf, _, _ = cheap_model_scores(tr, te, fc, rf100)

    # 概率校准(isotonic / sigmoid),仅用 train 的交叉验证,不碰 calibration 份
    rf_iso = CalibratedClassifierCV(
        RandomForestClassifier(n_estimators=10, max_depth=8, random_state=SEED, n_jobs=-1),
        method="isotonic", cv=5)
    rf_iso.fit(tr[fc].values, tr["label"].values)
    iso_proba = rf_iso.predict_proba(te[fc].values)
    iso_pred = rf_iso.classes_[iso_proba.argmax(1)]
    iso_conf = iso_proba.max(1)

    correct_dt = (dt_pred == ytrue)
    correct_rf = (rf_pred == ytrue)
    correct_rf100 = (rf100_pred == ytrue)
    correct_iso = (iso_pred == ytrue)

    # ============ B. 专家增益 ============
    log("=" * 70)
    log("B. 专家增益(test 集)")
    log("=" * 70)
    def overall(name, pred, corr):
        acc = accuracy_score(ytrue, pred); mf1 = f1_score(ytrue, pred, average="macro")
        log("  %-14s accuracy=%.4f  macro-F1=%.4f" % (name, acc, mf1))
        return acc, mf1
    log("[B1] 整体对比:")
    overall("DecisionTree", dt_pred, correct_dt)
    overall("RF(10)", rf_pred, correct_rf)
    overall("RF(100)", rf100_pred, correct_rf100)
    overall("DNN expert", dnn_pred, correct_dnn)

    log("\n[B1] 每类 recall(DT / RF10 / DNN):")
    log("  %-16s %8s %8s %8s" % ("class", "DT", "RF10", "DNN"))
    for lab in LABELS:
        r_dt = recall_score(ytrue, dt_pred, labels=[lab], average="macro", zero_division=0)
        r_rf = recall_score(ytrue, rf_pred, labels=[lab], average="macro", zero_division=0)
        r_dn = recall_score(ytrue, dnn_pred, labels=[lab], average="macro", zero_division=0)
        log("  %-16s %8.3f %8.3f %8.3f%s" % (lab, r_dt, r_rf, r_dn,
            "   <-- 模糊类" if lab in AMBIG else ""))

    log("\n[B2] 模糊类 streaming<->non_streaming 互判(行=真值, 列=预测):")
    pair = ["streaming", "non_streaming"]
    for name, pred in [("RF10", rf_pred), ("DNN", dnn_pred)]:
        cm = confusion_matrix(ytrue, pred, labels=pair)
        log("  %s:  str->str=%d str->non=%d | non->str=%d non->non=%d"
            % (name, cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]))

    log("\n[B3] 上交收益:")
    # 在 RF 判错的流上,DNN 正确率
    wrong = ~correct_rf
    log("  RF10 判错的流共 %d 条;其中 DNN 判对 %d 条 -> DNN 在'RF错'子集上正确率 = %.3f"
        % (wrong.sum(), (correct_dnn & wrong).sum(),
           (correct_dnn[wrong].mean() if wrong.sum() else 0)))
    # 在 RF 低置信(conf<阈)的流上,DNN 正确率 与 RF 正确率
    for thr in [0.5, 0.7, 0.9]:
        low = rf_conf < thr
        if low.sum():
            log("  RF10 conf<%.1f 的流 %d 条(占%.1f%%):RF 正确率=%.3f, DNN 正确率=%.3f"
                % (thr, low.sum(), 100 * low.mean(),
                   correct_rf[low].mean(), correct_dnn[low].mean()))

    # ============ C. 选择性 risk-coverage ============
    log("\n" + "=" * 70)
    log("C. 选择性 risk-coverage(门控=RF 得票比例;接受->RF判, 拒绝->DNN判)")
    log("=" * 70)
    acc_rf = accuracy_score(ytrue, rf_pred)
    acc_dnn = accuracy_score(ytrue, dnn_pred)
    log("  两端基准:纯RF(φ=1) e2e=%.4f ;纯DNN(φ=0) e2e=%.4f" % (acc_rf, acc_dnn))

    cov, aacc, e2e = selective_curve(rf_conf, correct_rf, correct_dnn)

    # oracle:完美门控(恰好把 RF 会判错的流全交 DNN)
    oracle_cov = correct_rf.mean()
    oracle_e2e = (correct_rf | correct_dnn).mean()
    log("  oracle 上界:完美门控覆盖率=%.4f(=RF精度),端到端=%.4f(RF对∪DNN对)" % (oracle_cov, oracle_e2e))

    # 运营点:接受集错误率 ≤ α
    log("\n[C-运营点] 接受集错误率 ≤ α 时的最大覆盖率 φ 与端到端精度:")
    log("  %-6s %10s %10s %12s %12s" % ("α", "φ(覆盖)", "conf阈", "接受集精度", "端到端精度"))
    op_rows = []
    for alpha in [0.01, 0.05, 0.10]:
        phi, thr, k = max_coverage_at_alpha(rf_conf, correct_rf, alpha)
        if k:
            acc_acc = correct_rf[rf_conf >= thr].mean()
            rej = rf_conf < thr
            e = (correct_rf[~rej].sum() + correct_dnn[rej].sum()) / len(ytrue)
        else:
            acc_acc, e = float("nan"), acc_dnn
        log("  %-6.0f%% %9.3f %10.3f %11.3f %12.3f" % (alpha * 100, phi, thr, acc_acc, e))
        op_rows.append(dict(alpha=alpha, coverage=phi, conf_thr=thr,
                            accepted_acc=float(acc_acc), e2e_acc=float(e)))

    # RF10 vs RF100 vs 校准:conf≥0.7 / 0.9 的覆盖率
    log("\n[C-做大可信子集] conf≥τ 的覆盖率(越大越好,且该子集需高精度):")
    log("  %-22s %12s %12s" % ("门控分数", "cov(conf≥0.7)", "cov(conf≥0.9)"))
    for name, c, corr in [("RF10(未校准)", rf_conf, correct_rf),
                          ("RF100(未校准)", rf100_conf, correct_rf100),
                          ("RF10+isotonic校准", iso_conf, correct_iso)]:
        c07, c09 = coverage_at_conf(c, 0.7), coverage_at_conf(c, 0.9)
        # 该子集精度
        a07 = corr[c >= 0.7].mean() if (c >= 0.7).any() else float("nan")
        a09 = corr[c >= 0.9].mean() if (c >= 0.9).any() else float("nan")
        log("  %-22s %7.3f(acc%.3f) %7.3f(acc%.3f)" % (name, c07, a07, c09, a09))

    # AURC(端到端精度对覆盖率的曲线下面积,越高越好)各门控
    def aurc_e2e(conf, corr_cheap):
        cc, aa, ee = selective_curve(conf, corr_cheap, correct_dnn)
        trap = getattr(np, "trapezoid", getattr(np, "trapz", None))
        return float(trap(ee, cc) / (cc[-1] - cc[0]))
    log("\n[C-AURC] 端到端精度-覆盖率曲线下均值(越高越好):")
    log("  RF10=%.4f  RF100=%.4f  RF10+iso=%.4f"
        % (aurc_e2e(rf_conf, correct_rf), aurc_e2e(rf100_conf, correct_rf100),
           aurc_e2e(iso_conf, correct_iso)))

    # ---- 画 risk-coverage 图 ----
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(cov, aacc, label="accepted-set accuracy (RF10 gate)", color="C0")
    ax.plot(cov, e2e, label="end-to-end accuracy (RF10 accept + DNN reject)", color="C1")
    _, aacc100, e2e100 = selective_curve(rf100_conf, correct_rf100, correct_dnn)
    ax.plot(cov, e2e100, "--", color="C2", label="end-to-end (RF100 gate)")
    ax.axhline(acc_rf, ls=":", color="gray", label="pure RF (φ=1)=%.3f" % acc_rf)
    ax.axhline(acc_dnn, ls=":", color="green", label="pure DNN (φ=0)=%.3f" % acc_dnn)
    ax.scatter([oracle_cov], [oracle_e2e], color="red", zorder=5,
               label="oracle gate e2e=%.3f" % oracle_e2e)
    ax.set_xlabel("coverage φ (fraction handled in-network by RF)")
    ax.set_ylabel("accuracy")
    ax.set_title("Selective risk-coverage: in-network RF + offload to DNN")
    ax.legend(fontsize=8, loc="lower center"); ax.grid(alpha=0.3)
    plt.tight_layout(); fig.savefig(os.path.join(FIG, "risk_coverage.png"), dpi=120)
    log("\n[fig] experiments/figures/risk_coverage.png")

    # 保存运营点 + 曲线数据
    with open(os.path.join(REPO, "experiments", "step3_metrics.txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    json.dump({"operating_points": op_rows, "oracle_cov": float(oracle_cov),
               "oracle_e2e": float(oracle_e2e), "pure_rf": float(acc_rf),
               "pure_dnn": float(acc_dnn)},
              open(os.path.join(PROC, "risk_coverage_summary.json"), "w"),
              indent=2, ensure_ascii=False)
    print("\n[risk_coverage] 指标已写入 experiments/step3_metrics.txt")


if __name__ == "__main__":
    main()
