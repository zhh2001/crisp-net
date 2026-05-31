#!/usr/bin/env python3
"""
l3fwd_demo.py — CRISP-Net 第 1 步「自有工作流关」端到端编排脚本

从零跑通自有数据面 + P4Runtime 控制面:
  1) 用 Mininet 起 1 交换机 (simple_switch_grpc, --no-p4) + 2 主机 (h1,h2) 拓扑
  2) 经 P4Runtime:SetForwardingPipelineConfig 推入编译好的 l3fwd 程序
  3) 经 P4Runtime:向 ipv4_lpm 灌入转发表项(含默认 drop)
  4) h1 ping h2,要求 0% 丢包
  5) 经 P4Runtime 读回出口包计数器 egress_pkt_counter,证明其非零
  6) 干净拆除网络

必须以 root 运行(Mininet 需要)。控制面统一走 P4Runtime(gRPC)。
"""

import os
import sys
import argparse

# ---- 让本脚本能 import 到 tutorials 的 Mininet/ P4Runtime 库 ----
TUTORIALS_UTILS = os.path.expanduser("~/tutorials/utils")
sys.path.insert(0, TUTORIALS_UTILS)
sys.path.insert(0, os.path.join(TUTORIALS_UTILS, "p4runtime_lib"))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "topo"))

from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.bmv2 as bmv2
import p4runtime_lib.helper as helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

from l3fwd_topo import L3FwdTopo, HOSTS, configure_hosts

GRPC_PORT = 50051
DEVICE_ID = 0

# s1 的转发表项:目的 IP/32 -> (改写后的目的 MAC, 出端口)
TABLE_ENTRIES = [
    dict(dst_ip="10.0.1.1", mac="08:00:00:00:01:11", port=1),  # 去 h1
    dict(dst_ip="10.0.2.2", mac="08:00:00:00:02:22", port=2),  # 去 h2
]


def log(msg):
    print("[l3fwd-demo] {}".format(msg), flush=True)


def program_switch(p4info_path, bmv2_json_path, dump_file):
    """经 P4Runtime 推送 pipeline 配置并灌表。返回 (helper, conn)。"""
    p4info_helper = helper.P4InfoHelper(p4info_path)

    conn = bmv2.Bmv2SwitchConnection(
        name="s1",
        address="127.0.0.1:{}".format(GRPC_PORT),
        device_id=DEVICE_ID,
        proto_dump_file=dump_file,
    )

    conn.MasterArbitrationUpdate()
    log("P4Runtime: MasterArbitrationUpdate OK,成为 master")

    conn.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=bmv2_json_path,
    )
    log("P4Runtime: SetForwardingPipelineConfig 完成(已推入 l3fwd 程序)")

    # 默认动作:drop
    conn.WriteTableEntry(p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        default_action=True,
        action_name="MyIngress.drop",
        action_params={},
    ))
    log("P4Runtime: 写入默认动作 drop")

    # LPM 转发表项
    for e in TABLE_ENTRIES:
        conn.WriteTableEntry(p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": (e["dst_ip"], 32)},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": e["mac"], "port": e["port"]},
        ))
        log("P4Runtime: 灌入表项 dst={}/32 -> port {} (dmac {})".format(
            e["dst_ip"], e["port"], e["mac"]))

    return p4info_helper, conn


def read_counter(p4info_helper, conn, index):
    """读回 egress_pkt_counter[index] 的 packet_count。"""
    counter_id = p4info_helper.get_counters_id("MyEgress.egress_pkt_counter")
    total = 0
    for response in conn.ReadCounters(counter_id, index):
        for entity in response.entities:
            total += entity.counter_entry.data.packet_count
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True)
    ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--sw-path", default="simple_switch_grpc")
    ap.add_argument("--cli", action="store_true", help="结束前进入 Mininet CLI")
    ap.add_argument("--log-console", action="store_true",
                    help="交换机开启 --log-console(逐包日志,调试用)")
    ap.add_argument("--logdir", default=os.path.join(REPO, "experiments", "logs"))
    args = ap.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    dump_file = os.path.join(args.logdir, "s1-p4runtime-requests.txt")

    topo = L3FwdTopo(
        sw_path=args.sw_path,
        grpc_port=GRPC_PORT,
        thrift_port=9090,
        log_file=os.path.join(args.logdir, "s1-switch.log"),
        log_console=args.log_console,
    )
    net = Mininet(topo=topo, switch=P4RuntimeSwitch,
                  link=TCLink, controller=None)

    rc = 1
    conn = None
    try:
        net.start()
        log("Mininet 已启动(s1 + h1 + h2)")
        configure_hosts(net, verbose=args.log_console)
        log("主机默认路由 + 静态 ARP 配置完成")

        # 给 grpc server 一点时间
        net.get("s1").cmd("sleep 1")

        p4info_helper, conn = program_switch(args.p4info, args.bmv2_json, dump_file)

        h1, h2 = net.get("h1"), net.get("h2")

        log("==== 关键验证:h1 ping -c3 h2 (10.0.2.2) ====")
        ping_out = h1.cmd("ping -c3 -W1 10.0.2.2")
        print(ping_out, flush=True)

        # 解析丢包率
        import re
        m = re.search(r"(\d+)% packet loss", ping_out)
        loss = m.group(1) if m else "?"
        ping_ok = (loss == "0")
        log("ping 丢包率 = {}%  -> {}".format(loss, "成功" if ping_ok else "失败"))

        # 读回计数器:index=2 (出向 h2) 与 index=1 (出向 h1,即回包)
        c2 = read_counter(p4info_helper, conn, 2)
        c1 = read_counter(p4info_helper, conn, 1)
        log("egress_pkt_counter[port=2 -> h2] = {} 包".format(c2))
        log("egress_pkt_counter[port=1 -> h1] = {} 包".format(c1))
        counter_ok = (c2 > 0 and c1 > 0)
        log("计数器非零 -> {}".format("成功" if counter_ok else "失败"))

        if args.cli:
            CLI(net)

        if ping_ok and counter_ok:
            log("==== 自有工作流关:PASS ====")
            rc = 0
        else:
            log("==== 自有工作流关:FAIL ====")
            rc = 2
    finally:
        if conn is not None:
            ShutdownAllSwitchConnections()
        net.stop()
        log("Mininet 已停止,网络清理完成")

    sys.exit(rc)


if __name__ == "__main__":
    main()
