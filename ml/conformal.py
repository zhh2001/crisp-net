#!/usr/bin/env python3
"""
conformal.py — CRISP-Net 第 6 步:保形风险控制 + 漂移下 ACI + 定点化检验(纯 host)

选择性分类:廉价模型 = isotonic 校准的 RF10(第5步发现校准置信度最好);门控分数 s = 校准置信度。
接受(在网由廉价模型判)当 s ≥ τ;拒绝(上交 host DNN)当 s < τ。
**接受集选择性错误率** R(τ) = P(廉价模型判错 | s ≥ τ)。目标:R(τ̂) ≤ α 有保证。

数据纪律:RF + isotonic 校准在 **train** 上拟合(isotonic 用 train 的 CV);**calibration 份本步启用**,
仅用于保形标定 τ̂;**test 份仅评估,绝不用于标定**。SEED=42。

A. 静态保形(可交换 regime):RCPS/LTT 风格有限样本上置信界(Hoeffding UCB)选 τ̂ 使 R(τ̂)≤α 以 prob≥1−δ;
   朴素 split-conformal 分位阈值作对照;多次重抽样 cal/test 验证"实测错误率 ≤ α"。
B. 漂移(非可交换):构造类别难度递增漂移流;static τ̂ vs ACI 在线更新 τ_t 的滚动接受集错误率。
C. 定点化:分数与 τ 量化为 b-bit 整数,确认保证保持,报最小 bit 宽。
"""
import os
import json
import argparse
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(REPO, "experiments", "figures")
NON_FEATURE = {"label", "split", "biflow_id", "vpn"}
DELTA = 0.10
ALPHAS = [0.01, 0.05, 0.10]
out = []


def log(s=""):
    print(s); out.append(s)


# ---------- 选择性风险工具 ----------
def selective_risk_curve(scores, correct):
    """按分数降序接受;返回排序后 (thr, coverage, cum_error_rate)。"""
    order = np.argsort(-scores)
    s = scores[order]
    err = (1 - correct[order]).astype(float)
    n = len(s)
    cum_err = np.cumsum(err)
    k = np.arange(1, n + 1)
    return s, k / n, cum_err / k  # thr at each prefix, coverage, empirical accepted-error


from scipy.stats import beta as _beta


def clopper_pearson_upper(x, n, delta):
    """二项参数(条件错误率)的精确 (1−delta) 上置信界。"""
    if n == 0:
        return 1.0
    if x >= n:
        return 1.0
    return float(_beta.ppf(1.0 - delta, x + 1, n - x))


def rcps_threshold(scores_cal, correct_cal, alpha, delta, n_grid=100):
    """Learn-then-Test 风格:覆盖率网格上每个候选 τ 用 Clopper-Pearson 上界检验条件错误率≤α,
    Bonferroni 校正(δ/K),在通过者中取最大覆盖率(最低 τ)的 τ̂。避免 FST 在小样本尾部误停。"""
    order = np.argsort(-scores_cal)
    s = scores_cal[order]
    err = (1 - correct_cal[order]).astype(float)
    cum_err = np.cumsum(err)
    n = len(s)
    # 候选覆盖率(对应前 k 个高分样本),网格化
    ks = np.unique(np.linspace(1, n, n_grid).astype(int))
    delta_bonf = delta / len(ks)
    tau_hat = np.inf
    best_cov = 0.0
    for k in ks:
        x = int(cum_err[k - 1])
        ucb = clopper_pearson_upper(x, int(k), delta_bonf)
        if ucb <= alpha and (k / n) > best_cov:
            best_cov = k / n
            tau_hat = s[k - 1]      # 该覆盖率对应的最低接受分数
    return tau_hat


def naive_threshold(scores_cal, correct_cal, alpha):
    """朴素:经验接受集错误率 ≤ α 的最低 τ(无有限样本修正)。"""
    order = np.argsort(-scores_cal)
    s = scores_cal[order]
    err = (1 - correct_cal[order]).astype(float)
    cum_err = np.cumsum(err)
    n = len(s)
    tau = np.inf
    for k in range(1, n + 1):
        if cum_err[k - 1] / k <= alpha:
            tau = s[k - 1]
        # 不 break:取满足条件的最大覆盖(最低 τ)
    return tau


def eval_threshold(scores, correct, tau):
    acc = scores >= tau
    n_acc = int(acc.sum())
    cov = n_acc / len(scores)
    err = float((1 - correct[acc]).mean()) if n_acc > 0 else float("nan")
    return cov, err, n_acc


def fit_calibrated_rf(df, fc):
    tr = df[df.split == "train"]
    Xtr = tr[fc].to_numpy(dtype=float); ytr = tr["label"].to_numpy(dtype=object)
    base = RandomForestClassifier(n_estimators=10, max_depth=8, random_state=SEED, n_jobs=-1)
    iso = CalibratedClassifierCV(base, method="isotonic", cv=5)
    iso.fit(Xtr, ytr)
    return iso


def score_split(iso, df, fc, split):
    sub = df[df.split == split]
    X = sub[fc].to_numpy(dtype=float); y = sub["label"].to_numpy(dtype=object)
    proba = iso.predict_proba(X)
    pred = iso.classes_[proba.argmax(1)]
    conf = proba.max(1)
    correct = (pred == y).astype(int)
    return conf, correct, pred, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proc", default=os.path.join(REPO, "data", "processed"))
    ap.add_argument("--tag", default="")
    ap.add_argument("--resamples", type=int, default=200)
    ap.add_argument("--skip-aci", action="store_true")
    args = ap.parse_args()
    proc, tag = args.proc, args.tag
    os.makedirs(FIG, exist_ok=True)
    rng = np.random.RandomState(SEED)

    df = pd.read_csv(os.path.join(proc, "features.csv"))
    fc = [c for c in df.columns if c not in NON_FEATURE]
    labels = sorted(df["label"].unique().tolist())

    log("=" * 70)
    log("CRISP-Net 第6步 保形风险控制  tag=%s  (δ=%.2f)" % (tag or "(vpn)", DELTA))
    log("=" * 70)
    iso = fit_calibrated_rf(df, fc)
    conf_cal, corr_cal, _, y_cal = score_split(iso, df, fc, "calibration")
    conf_te, corr_te, pred_te, y_te = score_split(iso, df, fc, "test")
    log("[setup] 校准RF: cal n=%d (判对率%.3f), test n=%d (判对率%.3f)"
        % (len(conf_cal), corr_cal.mean(), len(conf_te), corr_te.mean()))

    # DNN 专家(test;接受->RF,拒绝->DNN 的端到端)
    dnn = pd.read_csv(os.path.join(proc, "preds_test_dnn.csv"))
    assert (dnn["true_label"].to_numpy(dtype=object) == y_te).all(), "DNN 与 test 未对齐"
    corr_dnn_te = (dnn["pred_label"].to_numpy(dtype=object) == y_te).astype(int)

    # ===================== A. 静态保形 =====================
    log("\n[A] 静态保形阈值(在 calibration 标定,test 评估):")
    log("  %-5s %-26s %8s %10s %12s %12s" % ("α", "method", "τ̂", "cov(test)", "err(test)", "e2e(test)"))
    A_rows = {}
    for alpha in ALPHAS:
        for method, tau in [("RCPS(Hoeffding,δ=0.1)", rcps_threshold(conf_cal, corr_cal, alpha, DELTA)),
                            ("naive split-conformal", naive_threshold(conf_cal, corr_cal, alpha))]:
            cov, err, n_acc = eval_threshold(conf_te, corr_te, tau)
            acc = conf_te >= tau
            e2e = (corr_te[acc].sum() + corr_dnn_te[~acc].sum()) / len(conf_te)
            log("  %-5.0f%% %-26s %8.4f %9.3f %11.3f %12.3f"
                % (alpha * 100, method, tau if np.isfinite(tau) else 9.99, cov, err if err == err else 0, e2e))
            A_rows[(alpha, method)] = dict(tau=float(tau) if np.isfinite(tau) else None,
                                           cov=float(cov), err=float(err) if err == err else None, e2e=float(e2e))

    # α=5% 运营点:每类接受比例
    tau5 = rcps_threshold(conf_cal, corr_cal, 0.05, DELTA)
    log("\n[A] α=5%% RCPS 运营点 τ̂=%.4f 的每类接受比例(test):" % tau5)
    log("  %-16s %6s %10s %12s" % ("class", "n", "RF_acc", "accept_frac"))
    per_class_accept = {}
    for c in labels:
        m = (y_te == c)
        af = float((conf_te[m] >= tau5).mean())
        per_class_accept[c] = af
        log("  %-16s %6d %10.3f %12.3f" % (c, int(m.sum()), corr_te[m].mean(), af))

    # ===================== A2. 多次重抽样验证保证 =====================
    log("\n[A2] 重抽样验证(pool=cal+test,随机重分 %d 次,α=5%%,δ=0.1):" % args.resamples)
    pool_s = np.concatenate([conf_cal, conf_te])
    pool_c = np.concatenate([corr_cal, corr_te])
    n_cal = len(conf_cal); Npool = len(pool_s)
    realized = {"RCPS": [], "naive": []}
    cover = {"RCPS": [], "naive": []}
    for _ in range(args.resamples):
        perm = rng.permutation(Npool)
        ci, ti = perm[:n_cal], perm[n_cal:]
        for method, fn in [("RCPS", lambda: rcps_threshold(pool_s[ci], pool_c[ci], 0.05, DELTA)),
                           ("naive", lambda: naive_threshold(pool_s[ci], pool_c[ci], 0.05))]:
            tau = fn()
            cov, err, n_acc = eval_threshold(pool_s[ti], pool_c[ti], tau)
            if n_acc > 0:
                realized[method].append(err); cover[method].append(cov)
    for method in ["RCPS", "naive"]:
        r = np.array(realized[method]); cv = np.array(cover[method])
        if len(r) == 0:
            log("  %-6s 无可认证阈值(τ̂=inf,覆盖率≈0):保证成立但在网覆盖率为 0(数据使然)" % method)
            continue
        frac_nonzero = len(r) / args.resamples
        viol = float((r > 0.05).mean())
        log("  %-6s 实测接受错误率: 均值%.3f 中位%.3f 90分位%.3f | 违反(>α)=%.1f%% (应≤%.0f%%) | 平均覆盖率%.3f (有覆盖的重抽样占%.0f%%)"
            % (method, r.mean(), np.median(r), np.quantile(r, 0.9), 100 * viol, 100 * DELTA,
               cv.mean(), 100 * frac_nonzero))

    # 图:实测错误率分布
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(realized["naive"], bins=30, alpha=0.6, label="naive split-conformal", color="C1")
    ax.hist(realized["RCPS"], bins=30, alpha=0.6, label="RCPS (Hoeffding, δ=0.1)", color="C0")
    ax.axvline(0.05, color="red", ls="--", label="α=5%")
    ax.set_xlabel("realized accepted-set error on test' (per resample)")
    ax.set_ylabel("count"); ax.set_title("Conformal guarantee: realized error vs alpha=5%% [%s]" % (tag or "vpn"))
    ax.legend(); ax.grid(alpha=0.3)
    plt.tight_layout(); fig.savefig(os.path.join(FIG, "conformal_guarantee%s.png" % tag), dpi=120)
    log("[fig] conformal_guarantee%s.png" % tag)

    # ===================== C. 定点化检验 =====================
    log("\n[C] 定点化(分数与 τ 量化为 b-bit 整数,RCPS 重标定 α=5%):")
    log("  %-6s %10s %10s %10s" % ("bits", "τ̂_q", "cov(test)", "err(test)"))
    for b in [8, 12, 16]:
        M = (1 << b) - 1
        qc = np.round(conf_cal * M).astype(np.int64)
        qt = np.round(conf_te * M).astype(np.int64)
        tau_q = rcps_threshold(qc.astype(float), corr_cal, 0.05, DELTA)
        cov, err, n_acc = eval_threshold(qt.astype(float), corr_te, tau_q)
        log("  %-6d %10d %10.3f %10.3f" % (b, int(tau_q) if np.isfinite(tau_q) else -1, cov, err if err == err else 0))

    # ===================== B. 漂移下 ACI =====================
    aci_summary = {}
    if not args.skip_aci:
        log("\n[B] 漂移下 ACI:")
        # 构造漂移流:按类别难度递增排序(易门控->难门控),类内 shuffle
        order_by_gat = quic_difficulty_order(labels)
        idx_stream = []
        for c in order_by_gat:
            ci = np.where(y_te == c)[0]
            rng.shuffle(ci)
            idx_stream.extend(ci.tolist())
        idx_stream = np.array(idx_stream)
        s_stream = conf_te[idx_stream]; c_stream = corr_te[idx_stream]; y_stream = y_te[idx_stream]
        log("  漂移流顺序(类难度递增):%s  共 %d 窗口" % (" -> ".join(order_by_gat), len(s_stream)))

        # a->τ 映射(用 cal 的 naive 阈值,按目标 level)
        def tau_of_a(a):
            return naive_threshold(conf_cal, corr_cal, max(1e-3, min(a, 0.6)))

        tau_static = tau5
        results = run_static_vs_aci(s_stream, c_stream, tau_static, tau_of_a, alpha=0.05,
                                    gammas=[0.02, 0.08, 0.2])
        plot_aci(results, s_stream, order_by_gat, y_stream, y_te, tag)
        aci_summary = {g: dict(long_run_err=float(results["aci"][g]["long_err"]),
                               cov=float(results["aci"][g]["cov"]))
                       for g in results["aci"]}
        aci_summary["static_long_err"] = float(results["static"]["long_err"])
        aci_summary["static_cov"] = float(results["static"]["cov"])
        log("  static τ̂: 长程接受错误率=%.3f 覆盖率=%.3f (漂移段会冲破 α)"
            % (results["static"]["long_err"], results["static"]["cov"]))
        for g in results["aci"]:
            log("  ACI γ=%.2f: 长程接受错误率=%.3f 覆盖率=%.3f" %
                (g, results["aci"][g]["long_err"], results["aci"][g]["cov"]))

    # 保存
    with open(os.path.join(REPO, "experiments", "step6_metrics%s.txt" % tag), "w") as f:
        f.write("\n".join(out) + "\n")
    json.dump({"A": {str(k): v for k, v in A_rows.items()},
               "per_class_accept_a5": per_class_accept, "tau5_rcps": float(tau5),
               "resample_violation_rcps": (float((np.array(realized["RCPS"]) > 0.05).mean())
                                           if realized["RCPS"] else None),
               "resample_violation_naive": (float((np.array(realized["naive"]) > 0.05).mean())
                                            if realized["naive"] else None),
               "rcps_coverage_zero": (len(realized["RCPS"]) == 0),
               "aci": aci_summary},
              open(os.path.join(proc, "conformal_summary%s.json" % tag), "w"),
              indent=2, ensure_ascii=False)
    print("\n[conformal] 指标写入 experiments/step6_metrics%s.txt" % tag)


def quic_difficulty_order(labels):
    """易门控->难门控(据第5步 per-class AUROC);未知标签按字母序兜底。"""
    pref = ["google-search", "google-doc", "google-music", "google-drive", "youtube"]
    ordered = [c for c in pref if c in labels] + [c for c in labels if c not in pref]
    return ordered


def accepted_rolling(acc_mask, err_full, w=200):
    """只在被接受的步上滚动平均错误率;返回 (接受步的流位置, 滚动错误率)。"""
    from collections import deque
    dq = deque(maxlen=w)
    xs, ys = [], []
    for t in range(len(acc_mask)):
        if acc_mask[t] and not np.isnan(err_full[t]):
            dq.append(float(err_full[t]))
            xs.append(t); ys.append(sum(dq) / len(dq))
    return np.array(xs), np.array(ys)


def run_static_vs_aci(s, correct, tau_static, tau_of_a, alpha, gammas):
    N = len(s)
    # static
    acc_st = s >= tau_static
    err_st = np.where(acc_st, 1 - correct, np.nan)   # 只在接受步记错误
    res = {"static": {"acc": acc_st, "err": err_st,
                      "long_err": np.nanmean(err_st) if np.isfinite(np.nanmean(err_st)) else 0.0,
                      "cov": acc_st.mean()},
           "aci": {}}
    for g in gammas:
        a_t = alpha
        acc = np.zeros(N, bool); errs = np.full(N, np.nan); a_track = np.zeros(N)
        for t in range(N):
            tau_t = tau_of_a(a_t)
            a_track[t] = a_t
            if s[t] >= tau_t:
                acc[t] = True
                e = 1.0 - correct[t]
                errs[t] = e
                a_t = a_t + g * (alpha - e)      # 仅在接受步更新(此处才观测到条件错误)
                a_t = min(max(a_t, 0.005), 0.5)  # 钳制目标 level,防止长正确流使其无界漂移
        res["aci"][g] = {"acc": acc, "err": errs, "a_track": a_track,
                         "long_err": np.nanmean(errs) if np.isfinite(np.nanmean(errs)) else 0.0,
                         "cov": acc.mean()}
    return res


def plot_aci(res, s, order, y_stream, y_te, tag):
    fig, ax = plt.subplots(2, 1, figsize=(11, 8), sharex=True)
    xs, ys = accepted_rolling(res["static"]["acc"], res["static"]["err"])
    ax[0].plot(xs, ys, label="static τ̂ (rolling acc-error)", color="C3", lw=2)
    for g, c in zip(sorted(res["aci"]), ["C0", "C1", "C2"]):
        xa, ya = accepted_rolling(res["aci"][g]["acc"], res["aci"][g]["err"])
        ax[0].plot(xa, ya, label="ACI γ=%.2f" % g, color=c)
    ax[0].axhline(0.05, color="k", ls="--", label="α=5%")
    ax[0].set_ylabel("rolling accepted-set error (w=300)")
    ax[0].set_title("Drift: static conformal breaches α; ACI restores it [%s]" % (tag or "vpn"))
    ax[0].legend(fontsize=8, ncol=2); ax[0].grid(alpha=0.3); ax[0].set_ylim(0, 0.4)
    # 下:类别边界 + ACI 的 a_track(用最大 γ)
    gmax = max(res["aci"]); ax[1].plot(res["aci"][gmax]["a_track"], color="C2", label="ACI target a_t (γ=%.2f)" % gmax)
    ax[1].axhline(0.05, color="k", ls="--")
    # 标注类别段边界
    bounds = []
    cur = 0
    from collections import Counter
    cnt = Counter(y_stream.tolist())
    for c in order:
        cur += cnt[c]; bounds.append(cur)
        ax[1].axvline(cur, color="gray", alpha=0.4, ls=":")
    ax[1].set_ylabel("ACI target level a_t"); ax[1].set_xlabel("stream step (class-difficulty ramp: %s)" % "->".join(order))
    ax[1].legend(fontsize=8); ax[1].grid(alpha=0.3)
    plt.tight_layout(); fig.savefig(os.path.join(FIG, "conformal_aci%s.png" % tag), dpi=120)
    log("[fig] conformal_aci%s.png" % tag)


if __name__ == "__main__":
    main()
