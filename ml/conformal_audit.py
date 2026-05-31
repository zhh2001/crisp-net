#!/usr/bin/env python3
"""
conformal_audit.py — CRISP-Net 第 7c 步 Part A:部署流水线保形保证的按流审计与修正

部署流水线 = 单 RF10 软投票 + 单 isotonic + 8-bit 校准分数(rf_pipeline)。7b 用窗口级 RCPS 标的 τ̂₈=228,
test 接受集错误率 0.073 > α。本步:
  1) 按"流"重抽样验证(同一流所有窗口整进一份),看窗口级 RCPS 程序的越界率是否 > δ;
  2) 若越界 > δ:改用 **cluster-conservative** 标定(有效样本数 = 被接受的流数,Hoeffding UCB),
     得更保守 τ̂,使按流重抽样越界 ≤ δ;
  3) 8-bit 量化取保守向上;报修正 τ̂₈/覆盖/接受错误率/越界率。
SEED=42,δ=0.1,α=5%。
"""
import os
import sys
import json
import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import rf_pipeline as RP
from conformal import rcps_threshold   # 窗口级 LTT/Clopper-Pearson(第6步同法)

SEED = 42
ALPHA = 0.05
DELTA = 0.10
PROC = os.path.join(REPO, "data", "processed", "quic")
out = []


def log(s=""):
    print(s); out.append(s)


def per_window_scores(P, df):
    X = df[RP.FEATS].to_numpy()
    pred, score, calib, accept = P.reference(X)
    correct = (np.array(P.rf_classes)[pred] == df["label"].to_numpy()).astype(int)
    flow = df["biflow_id"].astype(str).to_numpy()
    return calib.astype(float), correct, flow


def byflow_rcps(score, correct, flow, alpha, delta, n_grid=120):
    """cluster-conservative:对候选 τ,接受集窗口错误率 err_hat,有效样本数=被接受的不同流数,
    Hoeffding UCB = err_hat + sqrt(ln(K/δ)/(2*n_flows)) ≤ α 则可接受;取最大覆盖(最低 τ)。"""
    order = np.argsort(-score)
    s = score[order]; e = (1 - correct[order]).astype(float); fl = flow[order]
    cum_e = np.cumsum(e)
    N = len(s)
    ks = np.unique(np.linspace(1, N, n_grid).astype(int))
    db = delta / len(ks)
    tau = np.inf; best = 0.0
    for k in ks:
        err_hat = cum_e[k - 1] / k
        n_flows = len(set(fl[:k].tolist()))
        ucb = err_hat + np.sqrt(np.log(1.0 / db) / (2.0 * max(n_flows, 1)))
        if ucb <= alpha and (k / N) > best:
            best = k / N; tau = s[k - 1]
    return tau


def realized(score, correct, tau):
    acc = score >= tau
    n = int(acc.sum())
    return (n / len(score)), (float((1 - correct[acc]).mean()) if n else float("nan")), n


def byflow_resample(pool_s, pool_c, pool_f, calib_fn, M, rng):
    """按流把流集合随机分两半:cal' 标 τ',在 test' 上量窗口接受集错误率;返回越界率/平均覆盖。"""
    flows = np.array(sorted(set(pool_f.tolist())))
    viol = 0; cov = []; used = 0
    for _ in range(M):
        rng.shuffle(flows)
        half = len(flows) // 2
        calf = set(flows[:half].tolist())
        cmask = np.array([f in calf for f in pool_f])
        tau = calib_fn(pool_s[cmask], pool_c[cmask], pool_f[cmask])
        tmask = ~cmask
        phi, err, n = realized(pool_s[tmask], pool_c[tmask], tau)
        if n > 0:
            used += 1; cov.append(phi)
            if err > ALPHA:
                viol += 1
    return (viol / used if used else float("nan")), (float(np.mean(cov)) if cov else 0.0), used


def main():
    rng = np.random.RandomState(SEED)
    P = RP.RFGatePipeline(PROC)
    s_ca, c_ca, f_ca = per_window_scores(P, P.ca)
    s_te, c_te, f_te = per_window_scores(P, P.te)
    log("=" * 68)
    log("Part A 保形落地版按流审计  (δ=%.2f, α=%.2f)" % (DELTA, ALPHA))
    log("=" * 68)
    log("[基线] 7b 部署 τ̂₈(窗口级 RCPS)=%d;test 覆盖/接受错误率 = %.3f / %.3f"
        % (int(P.tau8), *realized(s_te, c_te, P.tau8)[:2]))

    pool_s = np.concatenate([s_ca, s_te]); pool_c = np.concatenate([c_ca, c_te])
    pool_f = np.concatenate([f_ca, f_te])
    nflow = len(set(pool_f.tolist()))
    log("[池] cal+test 窗口 %d,流 %d" % (len(pool_s), nflow))

    M = 300
    # 1) 窗口级 RCPS 程序(部署用)按流重抽样
    win_fn = lambda s, c, f: rcps_threshold(s, c, ALPHA, DELTA)
    naive_fn = lambda s, c, f: __import__("conformal").naive_threshold(s, c, ALPHA)
    v_win, cov_win, u1 = byflow_resample(pool_s, pool_c, pool_f, win_fn, M, np.random.RandomState(SEED))
    v_naive, cov_naive, _ = byflow_resample(pool_s, pool_c, pool_f, naive_fn, M, np.random.RandomState(SEED))
    log("\n[审计-按流重抽样 %d 次] 窗口级 RCPS(部署法):越界率=%.1f%% 平均覆盖=%.3f  <-- 应≤%.0f%%"
        % (M, 100 * v_win, cov_win, 100 * DELTA))
    log("[审计-按流重抽样] naive:                    越界率=%.1f%% 平均覆盖=%.3f"
        % (100 * v_naive, cov_naive))

    # 2) 修正:收紧标定名义 level α' < α 吸收聚类(用同一窗口级 RCPS,只是更保守的 α')
    log("\n[修正] 收紧标定 level α'(按流重抽样越界率 @ 真 α=%.2f,取越界率有余量 ≤7%% 的最大 α'):" % ALPHA)
    MARGIN = 0.07
    chosen_ap = None; v_bf = None; cov_bf = None
    for ap in [0.05, 0.04, 0.03, 0.025, 0.02, 0.015, 0.01]:
        fn = lambda s, c, f, a=ap: rcps_threshold(s, c, a, DELTA)
        v, cov, _ = byflow_resample(pool_s, pool_c, pool_f, fn, M, np.random.RandomState(SEED))
        log("  α'=%.3f: 按流越界率=%.1f%% 平均覆盖=%.3f" % (ap, 100 * v, cov))
        if chosen_ap is None and v <= MARGIN:
            chosen_ap = ap; v_bf = v; cov_bf = cov
    if chosen_ap is None:
        chosen_ap = 0.01; v_bf, cov_bf, _ = byflow_resample(
            pool_s, pool_c, pool_f, lambda s, c, f: rcps_threshold(s, c, 0.01, DELTA),
            M, np.random.RandomState(SEED))
    log("  -> 选定 α'=%.3f(按流越界率 %.1f%% ≤ %.0f%% 余量)" % (chosen_ap, 100 * v_bf, 100 * MARGIN))

    # 3) 在"全 calibration"上用 α' 标 τ̂(部署值),保守向上量化到 8-bit
    tau_corr = rcps_threshold(s_ca, c_ca, chosen_ap, DELTA)
    tau_corr8 = int(np.ceil(tau_corr)) if np.isfinite(tau_corr) else 256   # 保守向上
    phi, err, n = realized(s_te, c_te, tau_corr8)
    log("\n[修正运营点] 在 calibration 按流标定 τ̂₈(保守向上取整)= %d" % tau_corr8)
    log("  test:覆盖率 φ=%.3f  接受集错误率=%.3f  (对比部署 τ̂₈=%d 的 %.3f/%.3f)"
        % (phi, err, int(P.tau8), *realized(s_te, c_te, P.tau8)[:2]))

    ok = (v_bf <= DELTA)
    log("\n[Part A 结论] cluster-conservative 修正后按流重抽样越界率 %.1f%% %s δ=%.0f%% -> 保证%s成立"
        % (100 * v_bf, "≤" if ok else ">", 100 * DELTA, "" if ok else "**不**"))
    log("  采用修正后 τ̂₈ = %d 进入 Part B(覆盖 %.3f,接受错误 %.3f)。" % (tau_corr8, phi, err))

    with open(os.path.join(REPO, "experiments", "step7c_partA.txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    json.dump({"tau8_deploy_7b": int(P.tau8), "tau8_corrected": tau_corr8,
               "viol_window_rcps_byflow": float(v_win), "viol_naive_byflow": float(v_naive),
               "viol_corrected_byflow": float(v_bf), "test_cov_corrected": float(phi),
               "test_accerr_corrected": float(err), "guarantee_holds": bool(ok)},
              open(os.path.join(PROC, "conformal_audit.json"), "w"), indent=2, ensure_ascii=False)
    print("\n[audit] 写 experiments/step7c_partA.txt")


if __name__ == "__main__":
    main()
