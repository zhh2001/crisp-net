#!/usr/bin/env python3
"""
dnn_expert.py — CRISP-Net 第 3 步:host DNN 专家(1D-CNN 序列模型)

与第 2 步**同一 train/test 划分**(按 biflow,无泄漏);**不读取 calibration 份**。
专家吃比树更丰富的表示:整段窗口的**逐包序列**(带符号包长 / 相邻 IAT / 方向 / TCP flags),
而树只用"前 8 包明细 + 32 包聚合"(序列的有损摘要);另把树也有的标量(proto_tcp、port_dst)
作为辅助输入,使 DNN 输入信息是树的超集 —— 任何增益都来自更完整的序列表示。

两种数据模式:
  - 窗口模式(默认):sequences.npz(W=32 窗口,与 features.csv 行对齐)+ features.csv 取标量。用于与树逐样本对比 + risk-coverage。
  - 自包含模式(--seq-file X.npz):X 内含 X_seq/seq_len/scalars/split/label/biflow_id;用于"更多包"按 biflow 变体。

训练用 **biflow 级 val 早停**(从 train 划出,绝不碰 calibration)。GPU,固定 SEED=42。
"""
import os
import argparse
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
from sklearn.metrics import (accuracy_score, f1_score, classification_report,
                             confusion_matrix, ConfusionMatrixDisplay)

SEED = 42
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(REPO, "data", "processed")
FIG = os.path.join(REPO, "experiments", "figures")
LABELS = ["mail", "meet", "non_streaming", "ssh", "streaming"]
LAB2I = {l: i for i, l in enumerate(LABELS)}


def set_seed():
    import random
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def normalize_seq(X):
    Xn = X.copy().astype(np.float32)
    Xn[:, :, 0] = np.clip(Xn[:, :, 0] / 1460.0, -2.0, 2.0)                         # signed_len
    Xn[:, :, 1] = np.log1p(np.clip(Xn[:, :, 1], 0, 60000)) / np.log1p(60000.0)     # iat
    return Xn


def load_window():
    d = np.load(os.path.join(PROC, "sequences.npz"), allow_pickle=True)
    X = normalize_seq(d["X_seq"]); seqlen = d["seq_len"].astype(np.int64)
    split = d["split"].astype(str)
    df = pd.read_csv(os.path.join(PROC, "features.csv"))
    assert len(df) == len(X) and (df["split"].to_numpy().astype(str) == split).all()
    y = df["label"].map(LAB2I).to_numpy()
    scal = np.stack([df["proto_tcp"].to_numpy().astype(np.float32),
                     np.clip(df["port_dst"].to_numpy().astype(np.float32), 0, 65535) / 65535.0], axis=1)
    bid = df["biflow_id"].to_numpy()
    return X, seqlen, scal, y, split, bid


def load_selfcontained(path):
    d = np.load(path, allow_pickle=True)
    X = normalize_seq(d["X_seq"]); seqlen = d["seq_len"].astype(np.int64)
    split = d["split"].astype(str)
    y = np.array([LAB2I[l] for l in d["label"]])
    scal = d["scalars"].astype(np.float32)
    bid = d["biflow_id"].astype(str)
    return X, seqlen, scal, y, split, bid


class SeqCNN(nn.Module):
    def __init__(self, n_ch=8, n_scal=2, n_cls=5, h=64):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(n_ch, h, 3, padding=1), nn.ReLU(),
            nn.Conv1d(h, h, 3, padding=1), nn.ReLU(),
            nn.Conv1d(h, 2 * h, 3, padding=1), nn.ReLU(),
        )
        self.head = nn.Sequential(
            nn.Linear(2 * (2 * h) + n_scal, 128), nn.ReLU(), nn.Dropout(0.4),
            nn.Linear(128, n_cls),
        )

    def forward(self, x_seq, mask, x_scal):
        z = self.conv(x_seq.transpose(1, 2))
        m = mask.unsqueeze(1)
        zmean = (z * m).sum(2) / m.sum(2).clamp(min=1)
        zmax = z.masked_fill(m == 0, -1e9).max(2).values
        return self.head(torch.cat([zmean, zmax, x_scal], 1))


def make_mask(seqlen, T):
    return (np.arange(T)[None, :] < seqlen[:, None]).astype(np.float32)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seq-file", default=None, help="自包含 npz;不给则用窗口模式")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--patience", type=int, default=25)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--tag", default="dnn")
    args = ap.parse_args()

    set_seed()
    os.makedirs(FIG, exist_ok=True)
    dev = "cuda" if torch.cuda.is_available() else "cpu"

    if args.seq_file:
        X, seqlen, scal, y, split, bid = load_selfcontained(args.seq_file)
    else:
        X, seqlen, scal, y, split, bid = load_window()
    T = X.shape[1]
    mask = make_mask(seqlen, T)
    print("[dnn] tag=%s  device=%s  T=%d  通道=%d" % (args.tag, dev, T, X.shape[2]))

    tr = split == "train"; te = split == "test"
    # ---- biflow 级 val 早停:从 train 划 15% biflow 作 val ----
    rng = np.random.RandomState(SEED)
    tr_bids = np.array(sorted(set(bid[tr])))
    rng.shuffle(tr_bids)
    n_val = max(1, int(0.15 * len(tr_bids)))
    val_bids = set(tr_bids[:n_val].tolist())
    is_val = np.array([(b in val_bids) for b in bid]) & tr
    is_trn = tr & (~is_val)
    print("[dnn] train=%d (trn=%d val=%d) test=%d (calibration 不用)"
          % (tr.sum(), is_trn.sum(), is_val.sum(), te.sum()))

    def to_t(a, long=False):
        t = torch.tensor(a, device=dev)
        return t.long() if long else t
    Xtr, Mtr, Str, Ytr = to_t(X[is_trn]), to_t(mask[is_trn]), to_t(scal[is_trn]), to_t(y[is_trn], True)
    Xv, Mv, Sv, Yv = to_t(X[is_val]), to_t(mask[is_val]), to_t(scal[is_val]), y[is_val]
    Xe, Me, Se, Ye = to_t(X[te]), to_t(mask[te]), to_t(scal[te]), y[te]

    model = SeqCNN(n_ch=X.shape[2]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    lossf = nn.CrossEntropyLoss()
    n = Xtr.shape[0]
    g = torch.Generator().manual_seed(SEED)
    best_f1, best_state, bad = -1.0, None, 0
    for ep in range(args.epochs):
        model.train()
        perm = torch.randperm(n, generator=g).to(dev)
        for i in range(0, n, args.batch):
            b = perm[i:i + args.batch]
            opt.zero_grad()
            loss = lossf(model(Xtr[b], Mtr[b], Str[b]), Ytr[b])
            loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            vp = model(Xv, Mv, Sv).argmax(1).cpu().numpy()
        vf1 = f1_score(Yv, vp, average="macro")
        if vf1 > best_f1 + 1e-4:
            best_f1 = vf1; best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}; bad = 0
        else:
            bad += 1
            if bad >= args.patience:
                print("[dnn] early stop @epoch %d  best val macro-F1=%.4f" % (ep + 1, best_f1)); break
    if best_state:
        model.load_state_dict(best_state)

    model.eval()
    with torch.no_grad():
        tr_acc = (model(Xtr, Mtr, Str).argmax(1).cpu().numpy() == y[is_trn]).mean()
        probs = torch.softmax(model(Xe, Me, Se), 1).cpu().numpy()
    ypred = np.array(LABELS)[probs.argmax(1)]; conf = probs.max(1)
    ytrue = np.array(LABELS)[Ye]
    acc = accuracy_score(ytrue, ypred); mf1 = f1_score(ytrue, ypred, average="macro")
    print("[dnn] TRAIN acc=%.4f | TEST acc=%.4f macro-F1=%.4f" % (tr_acc, acc, mf1))
    print(classification_report(ytrue, ypred, labels=LABELS, digits=3, zero_division=0))

    pd.DataFrame({"true_label": ytrue, "pred_label": ypred, "confidence": conf}).to_csv(
        os.path.join(PROC, "preds_test_%s.csv" % args.tag), index=False)
    np.savez_compressed(os.path.join(PROC, "%s_test_probs.npz" % args.tag),
                        probs=probs, classes=np.array(LABELS), true=ytrue, pred=ypred)
    cm = confusion_matrix(ytrue, ypred, labels=LABELS)
    disp = ConfusionMatrixDisplay(cm, display_labels=LABELS)
    fig, ax = plt.subplots(figsize=(8, 7))
    disp.plot(ax=ax, cmap="Greens", xticks_rotation=45, colorbar=False, values_format="d")
    ax.set_title("DNN expert [%s] (test) acc=%.3f macroF1=%.3f" % (args.tag, acc, mf1))
    plt.tight_layout(); fig.savefig(os.path.join(FIG, "confusion_matrix_%s.png" % args.tag), dpi=120)
    print("[dnn] 已存 (tag=%s)" % args.tag)


if __name__ == "__main__":
    main()
