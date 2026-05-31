#!/usr/bin/env bash
#
# run_l3fwd_demo.sh — CRISP-Net 第 1 步「自有工作流关」一键脚本
#
# 编译 p4/l3fwd.p4 -> 起 simple_switch_grpc 单交换机双主机拓扑
# -> 经 P4Runtime 灌入 ipv4_lpm 表项 -> h1 ping h2 -> 读回出口计数器(非零)。
#
# 用法(需 root,Mininet 要求):
#   sudo -E ./experiments/run_l3fwd_demo.sh
#   sudo -E ./experiments/run_l3fwd_demo.sh --cli      # 结束前进入 mininet CLI
#
# 注意:运行前请先在普通 shell 里  source ~/p4setup.bash  并加 -E 传递 PATH/venv,
#       否则脚本会自行尝试 source ~/p4setup.bash。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO/p4/build"
P4_SRC="$REPO/p4/l3fwd.p4"
P4INFO="$BUILD_DIR/l3fwd.p4info.txtpb"
BMV2_JSON="$BUILD_DIR/l3fwd.json"

# 若 p4c / python venv 不在 PATH,尝试加载工具链
if ! command -v p4c-bm2-ss >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  source "$HOME/p4setup.bash" 2>/dev/null || true
fi

echo "[run] 仓库根目录: $REPO"
echo "[run] 1) 编译 P4 程序 -> bmv2 JSON + P4Info"
mkdir -p "$BUILD_DIR"
p4c-bm2-ss --p4v 16 --p4runtime-files "$P4INFO" -o "$BMV2_JSON" "$P4_SRC"
echo "[run]    编译完成: $BMV2_JSON"

# 清理可能残留的交换机/网络命名空间
echo "[run] 2) 清理残留 mininet / simple_switch"
mn -c >/dev/null 2>&1 || true
pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true
sleep 1

echo "[run] 3) 启动拓扑 + P4Runtime 控制面 + ping + 读计数器"
PYTHON_BIN="$(command -v python3)"
"$PYTHON_BIN" "$REPO/experiments/l3fwd_demo.py" \
  --p4info "$P4INFO" \
  --bmv2-json "$BMV2_JSON" \
  --sw-path "$(command -v simple_switch_grpc)" \
  "$@"
RC=$?

echo "[run] 4) 收尾清理"
mn -c >/dev/null 2>&1 || true
pkill -9 -f simple_switch_grpc >/dev/null 2>&1 || true

echo "[run] demo 退出码: $RC"
exit $RC
