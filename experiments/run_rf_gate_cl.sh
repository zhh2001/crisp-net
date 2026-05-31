#!/usr/bin/env bash
# run_rf_gate_cl.sh — CRISP-Net 第 7c Part B 一键:闭环(RF门控+defer上送32包序列→host DNN)+端到端
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/p4/build"; P4INFO="$BUILD/rf_gate_cl.p4info.txtpb"; JSON="$BUILD/rf_gate_cl.json"
if ! command -v p4c-bm2-ss >/dev/null 2>&1; then source "$HOME/p4setup.bash" 2>/dev/null || true; fi
TAU=$(python3 -c "import json;print(json.load(open('$REPO/data/processed/quic/conformal_audit.json'))['tau8_corrected'])")
echo "[run] 0) 生成 rf_gate_cl.p4 + 表项(τ̂₈=$TAU,Part A 修正)"
python3 "$REPO/ml/rf_to_p4.py" --closed-loop --tau "$TAU"
echo "[run] 1) 编译"; mkdir -p "$BUILD"
p4c-bm2-ss --p4v 16 --p4runtime-files "$P4INFO" -o "$JSON" "$REPO/p4/rf_gate_cl.p4"
echo "[run] 2) 清理"; mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true; sleep 1
echo "[run] 3) 闭环 + 端到端"
python3 "$REPO/experiments/rf_gate_cl_demo.py" --p4info "$P4INFO" --bmv2-json "$JSON" \
  --sw-path "$(command -v simple_switch_grpc)" "$@"
RC=$?
echo "[run] 4) 收尾"; mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
echo "[run] 退出码 $RC"; exit $RC
