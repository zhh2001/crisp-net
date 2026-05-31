#!/usr/bin/env python3
"""
train_eval.py — CRISP-Net 第 2 步 / 轨道 1:训练 + 评估「廉价在网树模型」离线基线

输入:data/processed/features.csv —— 每行一条流,列含:
       <受限特征若干> + label(类别)+ split(train/calibration/test)
输出:
  - 控制台 + experiments/track1_metrics.txt:整体 accuracy / macro-F1 / 每类 P/R/F1、模型规模
  - experiments/figures/confusion_matrix_{dt,rf}.png:混淆矩阵
  - data/processed/preds_test_{dt,rf}.csv:test 每条预测的 真值/预测/置信度(供第3步保形)

关键说明:
  - 只用 train 训练、test 评估;**绝不读取 calibration 份**(留给第3步,避免泄漏)。
  - 固定随机种子,保证可复现。
  - 树深/叶子/特征数受限,便于将来编译进 P4。
"""

import os
import argparse
import numpy as np
import pandas as pd

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 非特征列(标识/标签/划分/来源),训练时排除
NON_FEATURE_COLS = {
    "label",
    "split",
    "biflow_id",
    "vpn",
    "flow_id",
    "src_ip",
    "dst_ip",
    "file",
    "src_file",
}


def load_split(csv_path):
    df = pd.read_csv(csv_path)
    feat_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    train = df[df["split"] == "train"]
    test = df[df["split"] == "test"]
    # 注意:calibration 故意不加载、不触碰
    assert len(train) > 0 and len(test) > 0, "train/test 划分为空"
    return df, feat_cols, train, test


def plot_confusion(y_true, y_pred, labels, title, out_png):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    disp = ConfusionMatrixDisplay(cm, display_labels=labels)
    fig, ax = plt.subplots(figsize=(1.2 * len(labels) + 3, 1.0 * len(labels) + 3))
    disp.plot(
        ax=ax, cmap="Blues", xticks_rotation=45, colorbar=False, values_format="d"
    )
    ax.set_title(title)
    plt.tight_layout()
    fig.savefig(out_png, dpi=120)
    plt.close(fig)


def per_class_table(y_true, y_pred, labels):
    rep = classification_report(
        y_true, y_pred, labels=labels, output_dict=True, zero_division=0
    )
    lines = []
    for lab in labels:
        r = rep[str(lab)] if str(lab) in rep else rep.get(lab, {})
        lines.append(
            "  %-18s P=%.3f  R=%.3f  F1=%.3f  (n=%d)"
            % (
                lab,
                r.get("precision", 0),
                r.get("recall", 0),
                r.get("f1-score", 0),
                int(r.get("support", 0)),
            )
        )
    return lines, rep


def confidence_scores(model, X):
    """单/集成树的置信度 = 预测类的后验概率(单树=叶子类纯度;RF=得票比例)。"""
    proba = model.predict_proba(X)
    return proba.max(axis=1)


def run_model(
    name, model, feat_cols, train, test, labels, report_lines, figdir, procdir
):
    Xtr, ytr = train[feat_cols].values, train["label"].values
    Xte, yte = test[feat_cols].values, test["label"].values
    model.fit(Xtr, ytr)
    ypred = model.predict(Xte)
    conf = confidence_scores(model, Xte)

    acc = accuracy_score(yte, ypred)
    mf1 = f1_score(yte, ypred, average="macro")

    report_lines.append("\n===== %s =====" % name)
    report_lines.append("整体 accuracy = %.4f   macro-F1 = %.4f" % (acc, mf1))

    # 模型规模(便于将来编译进 P4)
    if isinstance(model, DecisionTreeClassifier):
        report_lines.append(
            "树规模:depth=%d  leaves=%d  nodes=%d  features=%d"
            % (
                model.get_depth(),
                model.get_n_leaves(),
                model.tree_.node_count,
                len(feat_cols),
            )
        )
    else:
        depths = [t.get_depth() for t in model.estimators_]
        leaves = [t.get_n_leaves() for t in model.estimators_]
        report_lines.append(
            "森林规模:n_trees=%d  max_depth(限)=%s  实际depth max=%d  叶子合计=%d  features=%d"
            % (
                len(model.estimators_),
                str(model.max_depth),
                max(depths),
                sum(leaves),
                len(feat_cols),
            )
        )

    lines, rep = per_class_table(yte, ypred, labels)
    report_lines.append("每类指标:")
    report_lines.extend(lines)

    # 简单类 vs 模糊类(按 recall)
    recs = {lab: rep[lab]["recall"] for lab in labels if lab in rep}
    if recs:
        best = max(recs, key=recs.get)
        worst = min(recs, key=recs.get)
        report_lines.append(
            "简单类(recall最高)= %s (%.3f);模糊类(recall最低)= %s (%.3f);缺口 = %.3f"
            % (best, recs[best], worst, recs[worst], recs[best] - recs[worst])
        )

    # 混淆矩阵图(标题用 ASCII,避免缺字)
    is_dt = isinstance(model, DecisionTreeClassifier)
    suffix = "dt" if is_dt else "rf"
    ascii_title = (
        "DecisionTree" if is_dt else "RandomForest"
    ) + " (test) acc=%.3f macroF1=%.3f" % (acc, mf1)
    out_png = os.path.join(figdir, "confusion_matrix_%s.png" % suffix)
    plot_confusion(yte, ypred, labels, ascii_title, out_png)
    report_lines.append("混淆矩阵图:%s" % os.path.relpath(out_png, REPO))

    # 导出 test 每条预测的 真值/预测/置信度(供第3步保形阈值)
    out_csv = os.path.join(procdir, "preds_test_%s.csv" % suffix)
    pd.DataFrame({"true_label": yte, "pred_label": ypred, "confidence": conf}).to_csv(
        out_csv, index=False
    )
    report_lines.append(
        "test 预测+置信度已存:%s (%d 行)" % (os.path.relpath(out_csv, REPO), len(yte))
    )
    return acc, mf1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--features", default=os.path.join(REPO, "data", "processed", "features.csv")
    )
    ap.add_argument("--dt-max-depth", type=int, default=10)
    ap.add_argument("--rf-trees", type=int, default=10)
    ap.add_argument("--rf-max-depth", type=int, default=8)
    args = ap.parse_args()

    figdir = os.path.join(REPO, "experiments", "figures")
    procdir = os.path.join(REPO, "data", "processed")
    os.makedirs(figdir, exist_ok=True)
    os.makedirs(procdir, exist_ok=True)

    df, feat_cols, train, test = load_split(args.features)
    labels = sorted(df["label"].unique().tolist())

    report = []
    report.append("CRISP-Net 第2步/轨道1 — 离线基线评估")
    report.append("特征列(%d):%s" % (len(feat_cols), ", ".join(feat_cols)))
    report.append("类别(%d):%s" % (len(labels), ", ".join(map(str, labels))))
    n_calib = int((df["split"] == "calibration").sum())
    report.append(
        "划分:train=%d  test=%d  calibration=%d(本步未使用,留待第3步)"
        % (len(train), len(test), n_calib)
    )

    dt = DecisionTreeClassifier(max_depth=args.dt_max_depth, random_state=SEED)
    rf = RandomForestClassifier(
        n_estimators=args.rf_trees,
        max_depth=args.rf_max_depth,
        random_state=SEED,
        n_jobs=-1,
    )
    run_model(
        "决策树 DecisionTree(max_depth=%d)" % args.dt_max_depth,
        dt,
        feat_cols,
        train,
        test,
        labels,
        report,
        figdir,
        procdir,
    )
    run_model(
        "随机森林 RandomForest(%d×depth%d)" % (args.rf_trees, args.rf_max_depth),
        rf,
        feat_cols,
        train,
        test,
        labels,
        report,
        figdir,
        procdir,
    )

    text = "\n".join(report)
    print(text)
    out_txt = os.path.join(REPO, "experiments", "track1_metrics.txt")
    with open(out_txt, "w") as f:
        f.write(text + "\n")
    print("\n[train_eval] 指标已写入 %s" % os.path.relpath(out_txt, REPO))


if __name__ == "__main__":
    main()
