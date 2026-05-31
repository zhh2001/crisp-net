#!/usr/bin/env bash
#
# run_upload_demo.sh — CRISP-Net 第 2 步 / 轨道 2 一键脚本
#
# 编译 p4/upload.p4 -> 起 simple_switch_grpc(--cpu-port 510)1sw2host 拓扑
# -> crisp_controller 经 P4Runtime 推 pipeline/clone/digest/表项
# -> h1 发 N 个 UDP 探针触发上送 -> 统计 PacketIn/Digest 收到率 + 一路延迟
# -> 演示 PacketOut 回注 + 反应式写表。
#
# 用法(需 root):
#   sudo -E ./experiments/run_upload_demo.sh [--count 120]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/p4/build"
P4INFO="$BUILD/upload.p4info.txtpb"
JSON="$BUILD/upload.json"

if ! command -v p4c-bm2-ss >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  source "$HOME/p4setup.bash" 2>/dev/null || true
fi

echo "[run] 仓库: $REPO"
echo "[run] 1) 编译 p4/upload.p4"
mkdir -p "$BUILD"
p4c-bm2-ss --p4v 16 --p4runtime-files "$P4INFO" -o "$JSON" "$REPO/p4/upload.p4"

echo "[run] 2) 清理残留"
mn -c >/dev/null 2>&1 || true
pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
sleep 1

echo "[run] 3) 启动拓扑 + 控制器 + 触发 + 统计"
python3 "$REPO/experiments/upload_demo.py" \
  --p4info "$P4INFO" --bmv2-json "$JSON" \
  --sw-path "$(command -v simple_switch_grpc)" "$@"
RC=$?

echo "[run] 4) 收尾清理"
mn -c >/dev/null 2>&1 || true
pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
echo "[run] demo 退出码: $RC"
exit $RC
