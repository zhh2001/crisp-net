#!/usr/bin/env python3
"""
gating.py — CRISP-Net 第 4 步:学习型门控 + 门控可达性诊断

第 3 步发现瓶颈在门控(RF 得票比例排不出"树会不会判对")。本步训练一个**对错预测器**作门控,
看能否把现实门控推近 oracle,并判定瓶颈是"分数选得差(可修)"还是"对错本质不可预测(受限)"。

方法说明:
  - 门控**只用 40 维廉价特征**(数据平面可算的那套);可选加 RF 自己的得票比例(也在网可得)。**不使用 DNN 输出**。
  - "树是否判对"的标签用 **OOF**(GroupKFold by biflow)在 train 上得到,避免门控看到树的训练过拟合。
  - 复用第 3 步同一 train/test 划分与同一 RF10/DNN(DNN 预测从 preds_test_dnn.csv 读入);**calibration 只读不用**;SEED=42。
"""

import os
import json
import numpy as np
import pandas as pd

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_predict, GroupKFold
from sklearn.metrics import roc_auc_score, average_precision_score, accuracy_score

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(REPO, "data", "processed")
FIG = os.path.join(REPO, "experiments", "figures")
LABELS = ["mail", "meet", "non_streaming", "ssh", "streaming"]
AMBIG = {"streaming", "non_streaming", "meet"}
NON_FEATURE = {"label", "split", "biflow_id", "vpn"}
out = []


def log(s=""):
    print(s)
    out.append(s)


# ---------- 选择性曲线工具(接受->RF判, 拒绝->DNN判) ----------
def selective_curve(score, correct_cheap, correct_dnn, n_grid=200):
    order = np.argsort(-score)
    cc = correct_cheap[order].astype(float)
    cd = correct_dnn[order].astype(float)
    N = len(score)
    cum_cheap = np.cumsum(cc)
    cum_dnn_rej = cd.sum() - np.cumsum(cd)
    ks = np.unique(np.linspace(1, N, n_grid).astype(int))
    cov = ks / N
    acc_acc = cum_cheap[ks - 1] / ks
    e2e = (cum_cheap[ks - 1] + cum_dnn_rej[ks - 1]) / N
    return cov, acc_acc, e2e


def op_at_alpha(score, correct_cheap, correct_dnn, alpha):
    """接受集错误率 ≤ alpha 的最大覆盖率;返回 (phi, accepted_acc, e2e)。"""
    order = np.argsort(-score)
    cc = correct_cheap[order].astype(float)
    cum = np.cumsum(cc)
    N = len(score)
    best_k = 0
    for k in range(1, N + 1):
        if 1.0 - cum[k - 1] / k <= alpha:
            best_k = k
    if best_k == 0:
        return 0.0, float("nan"), accuracy_score(np.ones(N), correct_dnn)  # 全交 DNN
    thr = score[order][best_k - 1]
    acc_acc = correct_cheap[score >= thr].mean()
    rej = score < thr
    e2e = (correct_cheap[~rej].sum() + correct_dnn[rej].sum()) / N
    return best_k / N, acc_acc, e2e


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--proc", default=PROC, help="处理目录(含 features.csv / preds_test_dnn.csv)")
    ap.add_argument("--tag", default="", help="输出文件名后缀(如 _quic),勿覆盖 VPN 产物")
    args = ap.parse_args()
    proc, tag = args.proc, args.tag
    os.makedirs(FIG, exist_ok=True)
    df = pd.read_csv(os.path.join(proc, "features.csv"))
    fc = [c for c in df.columns if c not in NON_FEATURE]
    labels = sorted(df["label"].unique().tolist())
    # "模糊类"标注仅在 VPN 标签集时套用(QUIC 无预定义模糊集)
    ambig = AMBIG if set(labels) == set(LABELS) else set()
    tr = df[df.split == "train"].reset_index(drop=True)
    te = df[df.split == "test"].reset_index(drop=True)
    # 强制转 numpy(pandas3+pyarrow 后端的字符串列会破坏 sklearn 的分组索引)
    Xtr = tr[fc].to_numpy(dtype=float)
    ytr = tr["label"].to_numpy(dtype=object)
    gtr = tr["biflow_id"].to_numpy(dtype=object)
    Xte = te[fc].to_numpy(dtype=float)
    yte = te["label"].to_numpy(dtype=object)

    # ---- 被门控的廉价模型:RF10(与第3步一致)----
    rf = RandomForestClassifier(
        n_estimators=10, max_depth=8, random_state=SEED, n_jobs=-1
    )

    # OOF(GroupKFold by biflow)得到 train 上无偏的"对/错"标签
    gkf = GroupKFold(n_splits=5)
    oof_pred = cross_val_predict(
        rf, Xtr, ytr, groups=gtr, cv=gkf, method="predict", n_jobs=-1
    )
    gate_y_tr = (oof_pred == ytr).astype(int)  # 1=RF 判对
    log(
        "[A] OOF(GroupKFold by biflow) train 对错标签:RF 判对率=%.3f (n=%d)"
        % (gate_y_tr.mean(), len(gate_y_tr))
    )

    # 在 full train 上拟合 RF,得到 test 预测/概率(门控的被预测对象)
    rf.fit(Xtr, ytr)
    rf_proba_te = rf.predict_proba(Xte)
    rf_pred_te = rf.classes_[rf_proba_te.argmax(1)]
    correct_rf = (rf_pred_te == yte).astype(int)
    log("[A] RF10 test accuracy=%.4f" % correct_rf.mean())

    # DNN 专家预测(第3步,廉价特征之外;仅用于'拒绝'分支与 oracle)
    dnn = pd.read_csv(os.path.join(proc, "preds_test_dnn.csv"))
    assert (dnn["true_label"].values == yte).all()
    correct_dnn = (dnn["pred_label"].values == yte).astype(int)

    # ---- 训练学习型门控(只用廉价特征;另做一个额外可用 RF 得票比例的变体)----
    rf_conf_tr_oof = None
    # 标量门控特征:廉价 40 维。变体 +conf:再拼 RF OOF 得票比例(在网也可得)
    oof_proba = cross_val_predict(
        rf, Xtr, ytr, groups=gtr, cv=gkf, method="predict_proba", n_jobs=-1
    )
    conf_tr = oof_proba.max(1)
    conf_te = rf_proba_te.max(1)

    gates = {
        "LogReg(40feat)": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2000, C=1.0, random_state=SEED),
        ),
        "DT(40feat,d8)": DecisionTreeClassifier(max_depth=8, random_state=SEED),
        "RF(40feat)": RandomForestClassifier(
            n_estimators=200, max_depth=8, random_state=SEED, n_jobs=-1
        ),
        "RF(40feat+conf)": RandomForestClassifier(
            n_estimators=200, max_depth=8, random_state=SEED, n_jobs=-1
        ),
    }
    gate_scores_te = {}
    log("\n[A] 学习型门控:预测'RF 是否判对'(test 上 AUROC / AUPRC):")
    base_rate = correct_rf.mean()
    log("    (test 上 RF 判对基率=%.3f,AUPRC 随机基线≈该值)" % base_rate)
    for name, mdl in gates.items():
        if name.endswith("+conf"):
            Xg_tr = np.hstack([Xtr, conf_tr[:, None]])
            Xg_te = np.hstack([Xte, conf_te[:, None]])
        else:
            Xg_tr, Xg_te = Xtr, Xte
        mdl.fit(Xg_tr, gate_y_tr)
        p_te = mdl.predict_proba(Xg_te)[:, 1]
        gate_scores_te[name] = p_te
        au = roc_auc_score(correct_rf, p_te)
        ap = average_precision_score(correct_rf, p_te)
        log("    %-18s AUROC=%.3f  AUPRC=%.3f" % (name, au, ap))

    # 选最佳学习门控(按 AUROC)
    best_gate = max(
        gate_scores_te, key=lambda k: roc_auc_score(correct_rf, gate_scores_te[k])
    )
    log("    -> 最佳学习门控:%s" % best_gate)

    # ---- 其它门控分数 ----
    # margin = top1 - top2
    sp = np.sort(rf_proba_te, axis=1)
    margin = sp[:, -1] - sp[:, -2]
    # 负熵
    eps = 1e-12
    neg_entropy = (rf_proba_te * np.log(rf_proba_te + eps)).sum(
        1
    )  # = -entropy,越大越自信
    # 校准后置信度(isotonic,仅 train CV)
    iso = CalibratedClassifierCV(
        RandomForestClassifier(
            n_estimators=10, max_depth=8, random_state=SEED, n_jobs=-1
        ),
        method="isotonic",
        cv=5,
    ).fit(Xtr, ytr)
    iso_conf = iso.predict_proba(Xte).max(1)

    score_set = {
        "RF vote-fraction (baseline)": conf_te,
        "RF margin (top1-top2)": margin,
        "RF neg-entropy": neg_entropy,
        "RF isotonic-calibrated": iso_conf,
        "Learned gate [%s]" % best_gate: gate_scores_te[best_gate],
    }

    # ---- B. risk-coverage 对比 + 运营点 ----
    acc_rf = correct_rf.mean()
    acc_dnn = correct_dnn.mean()
    oracle_cov = acc_rf
    oracle_e2e = (correct_rf | correct_dnn).mean()
    log(
        "\n[B] 两端:纯RF=%.4f 纯DNN=%.4f ;oracle 完美门控 e2e=%.4f(+%.1fpt over 纯RF)"
        % (acc_rf, acc_dnn, oracle_e2e, 100 * (oracle_e2e - acc_rf))
    )

    log("\n[B] 各门控在 α 运营点的 覆盖率φ / 接受集精度 / 端到端精度:")
    head = "  %-30s" % "gate score" + "".join(
        "   α=%d%%:φ/acc_acc/e2e" % int(a * 100) for a in [0.01, 0.05, 0.10]
    )
    log(head)
    op_table = {}
    for name, s in score_set.items():
        row = "  %-30s" % name
        op_table[name] = {}
        for a in [0.01, 0.05, 0.10]:
            phi, aa, e2e = op_at_alpha(s, correct_rf, correct_dnn, a)
            row += "  %.3f/%.3f/%.3f" % (phi, aa if aa == aa else float("nan"), e2e)
            op_table[name]["alpha_%d" % int(a * 100)] = dict(
                phi=float(phi), accepted_acc=float(aa), e2e=float(e2e)
            )
        log(row)

    # 救回多少 oracle 头空间(以 α=5% 端到端计)
    base5 = op_at_alpha(conf_te, correct_rf, correct_dnn, 0.05)
    best5 = op_at_alpha(gate_scores_te[best_gate], correct_rf, correct_dnn, 0.05)
    log(
        "\n[B] α=5%%:基线RF置信 φ=%.3f e2e=%.3f → 学习门控 φ=%.3f e2e=%.3f"
        % (base5[0], base5[2], best5[0], best5[2])
    )
    headroom = oracle_e2e - acc_rf
    recovered = best5[2] - acc_rf
    log(
        "    覆盖率:%.1f%% → %.1f%%(×%.1f);端到端救回 %.1fpt / oracle 头空间 %.1fpt = %.0f%%"
        % (
            100 * base5[0],
            100 * best5[0],
            (best5[0] / base5[0] if base5[0] > 0 else float("inf")),
            100 * recovered,
            100 * headroom,
            100 * recovered / headroom if headroom > 0 else 0,
        )
    )

    # ---- 画 risk-coverage 对比图 ----
    fig, ax = plt.subplots(1, 2, figsize=(14, 6))
    for name, s in score_set.items():
        cov, aa, e2e = selective_curve(s, correct_rf, correct_dnn)
        ax[0].plot(cov, aa, label=name)
        ax[1].plot(cov, e2e, label=name)
    for a in ax:
        a.axhline(acc_rf, ls=":", color="gray", label="pure RF=%.3f" % acc_rf)
        a.axhline(acc_dnn, ls=":", color="green", label="pure DNN=%.3f" % acc_dnn)
    ax[1].scatter(
        [oracle_cov],
        [oracle_e2e],
        color="red",
        zorder=5,
        label="oracle e2e=%.3f" % oracle_e2e,
    )
    ax[0].set_title("accepted-set accuracy vs coverage")
    ax[0].set_xlabel("coverage φ")
    ax[0].set_ylabel("accuracy")
    ax[1].set_title("end-to-end accuracy vs coverage (accept→RF, reject→DNN)")
    ax[1].set_xlabel("coverage φ")
    for a in ax:
        a.grid(alpha=0.3)
        a.legend(fontsize=7, loc="lower left")
    plt.suptitle("CRISP-Net step4: learned gating vs confidence scores")
    plt.tight_layout()
    fig.savefig(os.path.join(FIG, "gating_risk_coverage%s.png" % tag), dpi=120)
    log("\n[fig] experiments/figures/gating_risk_coverage%s.png" % tag)

    # ---- C. 按类别拆解可门控性 ----
    log("\n[C] 按真实类别拆解(门控=%s):" % best_gate)
    log(
        "  %-15s %5s %8s %10s %14s"
        % ("class", "n", "RF_acc", "gateAUROC", "cov@α5%(类内)")
    )
    gscore = gate_scores_te[best_gate]
    # α=5% 全局阈值(用最佳门控)
    phi5, _, _ = op_at_alpha(gscore, correct_rf, correct_dnn, 0.05)
    # 全局阈值 = 使覆盖率=phi5 的分数阈
    thr5 = (
        np.sort(gscore)[::-1][max(0, int(round(phi5 * len(gscore))) - 1)]
        if phi5 > 0
        else np.inf
    )
    for c in labels:
        m = yte == c
        n = int(m.sum())
        rfa = correct_rf[m].mean()
        cr = correct_rf[m]
        if cr.min() != cr.max():
            au = roc_auc_score(cr, gscore[m])
        else:
            au = float("nan")  # 该类全对或全错,AUROC 无定义
        cov_c = float((gscore[m] >= thr5).mean())
        log(
            "  %-15s %5d %8.3f %10s %14.3f%s"
            % (
                c,
                n,
                rfa,
                ("%.3f" % au) if au == au else "  n/a",
                cov_c,
                "  <-- 模糊" if c in ambig else "",
            )
        )

    with open(os.path.join(REPO, "experiments", "step4_metrics%s.txt" % tag), "w") as f:
        f.write("\n".join(out) + "\n")
    json.dump(
        {
            "oracle_e2e": float(oracle_e2e),
            "pure_rf": float(acc_rf),
            "pure_dnn": float(acc_dnn),
            "best_gate": best_gate,
            "operating_points": op_table,
            "alpha5_baseline": dict(phi=float(base5[0]), e2e=float(base5[2])),
            "alpha5_learned": dict(phi=float(best5[0]), e2e=float(best5[2])),
        },
        open(os.path.join(proc, "gating_summary%s.json" % tag), "w"),
        indent=2,
        ensure_ascii=False,
    )
    print("\n[gating] 指标已写入 experiments/step4_metrics.txt")


if __name__ == "__main__":
    main()
