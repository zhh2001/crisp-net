#!/usr/bin/env bash
# run_rf_gate.sh — CRISP-Net 第 7b 步一键脚本:RF→P4 生成 -> 编译 -> 起交换机 -> 灌表+τ -> 驱动 -> 三级一致性
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/p4/build"; P4INFO="$BUILD/rf_gate.p4info.txtpb"; JSON="$BUILD/rf_gate.json"
if ! command -v p4c-bm2-ss >/dev/null 2>&1; then source "$HOME/p4setup.bash" 2>/dev/null || true; fi
echo "[run] 0) 生成 rf_gate.p4 + 表项(从 sklearn RF10)"
python3 "$REPO/ml/rf_to_p4.py"
echo "[run] 1) 编译 rf_gate.p4"
mkdir -p "$BUILD"
p4c-bm2-ss --p4v 16 --p4runtime-files "$P4INFO" -o "$JSON" "$REPO/p4/rf_gate.p4"
echo "[run] 2) 清理残留"; mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true; sleep 1
echo "[run] 3) 起拓扑 + 灌表 + 驱动 + 三级一致性"
python3 "$REPO/experiments/rf_gate_demo.py" --p4info "$P4INFO" --bmv2-json "$JSON" \
  --sw-path "$(command -v simple_switch_grpc)" "$@"
RC=$?
echo "[run] 4) 收尾"; mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
echo "[run] 退出码 $RC"; exit $RC
