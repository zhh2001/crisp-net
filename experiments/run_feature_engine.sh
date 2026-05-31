#!/usr/bin/env bash
# run_feature_engine.sh — CRISP-Net 第 7a 步一键脚本
# 编译 feature_engine.p4 -> 起 simple_switch_grpc 1sw2host -> 控制器收 digest
# -> h1 发 QUIC 测试流合成报文 -> 在网特征 vs 离线特征逐项一致性验证。
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/p4/build"; P4INFO="$BUILD/feature_engine.p4info.txtpb"; JSON="$BUILD/feature_engine.json"
if ! command -v p4c-bm2-ss >/dev/null 2>&1; then source "$HOME/p4setup.bash" 2>/dev/null || true; fi
echo "[run] 1) 编译 p4/feature_engine.p4"
mkdir -p "$BUILD"
p4c-bm2-ss --p4v 16 --p4runtime-files "$P4INFO" -o "$JSON" "$REPO/p4/feature_engine.p4"
echo "[run] 2) 清理残留"
mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true; sleep 1
echo "[run] 3) 起拓扑 + 控制器 + 驱动 + 一致性验证"
python3 "$REPO/experiments/feature_engine_demo.py" --p4info "$P4INFO" --bmv2-json "$JSON" \
  --sw-path "$(command -v simple_switch_grpc)" "$@"
RC=$?
echo "[run] 4) 收尾"; mn -c >/dev/null 2>&1 || true; pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
echo "[run] 退出码 $RC"; exit $RC
