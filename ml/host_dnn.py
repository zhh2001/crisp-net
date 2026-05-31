#!/usr/bin/env python3
"""
host_dnn.py — CRISP-Net 第 7c 步:host DNN 专家服务(第3步 1D-CNN),对上送的逐包序列做预测。

在 QUIC train(sequences.npz split=train)上训练第3步同款 SeqCNN(biflow 级 val 早停),
对外提供 predict(X_seq[N,32,8]) -> 类别标签。复现第3步 DNN 口径(scalars proto/port=0)。
"""
import os
import sys
import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import torch
import torch.nn as nn
from sklearn.metrics import f1_score
import dnn_expert as DE   # SeqCNN / normalize_seq / make_mask / set_seed

SEED = 42


class HostDNN:
    def __init__(self, proc):
        DE.set_seed()
        self.dev = "cuda" if torch.cuda.is_available() else "cpu"
        X, seqlen, scal, y, split, bid, labels = DE.load_window(proc)
        self.labels = labels
        T = X.shape[1]; mask = DE.make_mask(seqlen, T)
        tr = split == "train"
        rng = np.random.RandomState(SEED)
        tr_b = np.array(sorted(set(bid[tr]))); rng.shuffle(tr_b)
        nval = max(1, int(0.15 * len(tr_b))); val_b = set(tr_b[:nval].tolist())
        is_val = np.array([(b in val_b) for b in bid]) & tr
        is_trn = tr & (~is_val)
        t = lambda a, lo=False: (torch.tensor(a, device=self.dev).long() if lo else torch.tensor(a, device=self.dev))
        Xtr, Mtr, Str, Ytr = t(X[is_trn]), t(mask[is_trn]), t(scal[is_trn]), t(y[is_trn], True)
        Xv, Mv, Sv, Yv = t(X[is_val]), t(mask[is_val]), t(scal[is_val]), y[is_val]
        self.model = DE.SeqCNN(n_ch=X.shape[2]).to(self.dev)
        opt = torch.optim.Adam(self.model.parameters(), lr=1e-3, weight_decay=1e-4)
        lossf = nn.CrossEntropyLoss(); n = Xtr.shape[0]
        g = torch.Generator().manual_seed(SEED)
        best, best_state, bad = -1, None, 0
        for ep in range(200):
            self.model.train()
            perm = torch.randperm(n, generator=g).to(self.dev)
            for i in range(0, n, 256):
                b = perm[i:i + 256]; opt.zero_grad()
                loss = lossf(self.model(Xtr[b], Mtr[b], Str[b]), Ytr[b]); loss.backward(); opt.step()
            self.model.eval()
            with torch.no_grad():
                vp = self.model(Xv, Mv, Sv).argmax(1).cpu().numpy()
            f = f1_score(Yv, vp, average="macro")
            if f > best + 1e-4:
                best = f; best_state = {k: v.detach().clone() for k, v in self.model.state_dict().items()}; bad = 0
            else:
                bad += 1
                if bad >= 25:
                    break
        if best_state:
            self.model.load_state_dict(best_state)
        self.model.eval()
        print("[host_dnn] 训练完成(val macroF1=%.4f, dev=%s)" % (best, self.dev))

    def predict(self, X_seq):
        """X_seq: [N,32,8] 原始(signed_len, iat_ms, dir, flags...);scalars=0(QUIC)。返回类别标签。"""
        if len(X_seq) == 0:
            return np.array([], dtype=object)
        Xn = DE.normalize_seq(np.asarray(X_seq, dtype=np.float32))
        seqlen = np.full(len(Xn), Xn.shape[1], dtype=np.int64)
        mask = DE.make_mask(seqlen, Xn.shape[1])
        scal = np.zeros((len(Xn), 2), dtype=np.float32)
        with torch.no_grad():
            probs = torch.softmax(self.model(torch.tensor(Xn, device=self.dev),
                                             torch.tensor(mask, device=self.dev),
                                             torch.tensor(scal, device=self.dev)), 1).cpu().numpy()
        return np.array(self.labels)[probs.argmax(1)]
