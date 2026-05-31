#!/usr/bin/env python3
"""
upload_demo.py — CRISP-Net 第 2 步 / 轨道 2 端到端验证编排

  1) 起 1sw2host 拓扑(simple_switch_grpc --cpu-port 510)
  2) crisp_controller 经 P4Runtime 推 pipeline / clone / digest / 转发表 / monitor 表
  3) 健康检查:h1 ping h2(确认正常转发未被打断)
  4) 从 h1 发 N(默认120)个 UDP 探针触发上送,统计 PacketIn / Digest 收到率
  5) 估算一路上送延迟(探针负载内嵌时间戳)
  6) 演示反向动作:PacketOut 回注 + 据上送内容写一条 monitor 表项
  7) 读回数据平面 upload_counter 交叉核对触发次数
  8) 干净拆除

必须 root 运行。控制面统一 P4Runtime。
"""
import os
import sys
import time
import argparse
import statistics

TUTORIALS_UTILS = os.path.expanduser("~/tutorials/utils")
sys.path.insert(0, TUTORIALS_UTILS)
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "topo"))
sys.path.insert(0, os.path.join(REPO, "control"))

from mininet.net import Mininet
from mininet.link import TCLink

from p4runtime_switch import P4RuntimeSwitch
from upload_topo import UploadTopo, configure_hosts
from crisp_controller import CrispUploadController


def log(m): print("[upload-demo] %s" % m, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True)
    ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--sw-path", default="simple_switch_grpc")
    ap.add_argument("--count", type=int, default=120)
    ap.add_argument("--interval", type=float, default=0.02)
    ap.add_argument("--logdir", default=os.path.join(REPO, "experiments", "logs"))
    args = ap.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    dump = os.path.join(args.logdir, "s1-upload-p4runtime.txt")

    topo = UploadTopo(sw_path=args.sw_path, grpc_port=50051, thrift_port=9090,
                      log_file=os.path.join(args.logdir, "s1-upload.log"))
    net = Mininet(topo=topo, switch=P4RuntimeSwitch, link=TCLink, controller=None)

    rc = 1
    ctrl = None
    try:
        net.start()
        configure_hosts(net)
        net.get("s1").cmd("sleep 1")
        log("Mininet 已启动(s1 + h1 + h2)")

        # ---- 控制器:推 pipeline + clone + digest + 表项 ----
        ctrl = CrispUploadController(args.p4info, args.bmv2_json,
                                     address="127.0.0.1:50051", proto_dump_file=dump)
        ctrl.install_pipeline()
        log("P4Runtime: SetForwardingPipelineConfig 完成(upload.p4 已推入)")
        ctrl.add_clone_session()
        ctrl.enable_digest()
        ctrl.add_default_drop()
        ctrl.add_forward_entry("10.0.1.1", "08:00:00:00:01:11", 1)
        ctrl.add_forward_entry("10.0.2.2", "08:00:00:00:02:22", 2)
        ctrl.add_monitor_entry("10.0.2.2")
        log("P4Runtime: clone session(->CPU 510)、digest 使能、ipv4_lpm、monitor(dst=10.0.2.2) 均已装载")
        ctrl.start_receivers()

        h1, h2 = net.get("h1"), net.get("h2")

        # ---- 健康检查:正常转发仍工作 ----
        ping = h1.cmd("ping -c2 -W1 10.0.2.2")
        import re
        m = re.search(r"(\d+)% packet loss", ping)
        ping_loss = m.group(1) if m else "?"
        log("健康检查 h1->h2 ping 丢包率 = %s%%" % ping_loss)

        # 这两个 ping 也命中 monitor(dst=10.0.2.2),会产生上送;清零控制器侧计数后再做正式触发测试
        time.sleep(0.5)
        with ctrl.lock:
            ctrl.packetin_count = 0; ctrl.digest_count = 0
            ctrl.packetin_records.clear(); ctrl.digest_records.clear()
            ctrl.packetin_latencies.clear()

        # 数据平面 upload_counter 是硬件累计值(不清零),取触发前基线,后面用差值核对
        cid = ctrl.helper.get_counters_id("MyIngress.upload_counter")

        def read_dp_uploads():
            tot = 0
            for resp in ctrl.conn.ReadCounters(cid, 1):   # index = ingress_port 1 (h1)
                for e in resp.entities:
                    tot += e.counter_entry.data.packet_count
            return tot
        dp_before = read_dp_uploads()

        # ---- 正式触发:h1 发 N 个 UDP 探针 ----
        N = args.count
        log("==== 触发测试:h1 发 %d 个 UDP 探针 -> 10.0.2.2:9999 ====" % N)
        sender = os.path.join(REPO, "experiments", "probe_sender.py")
        out = h1.cmd("python3 %s --dst 10.0.2.2 --port 9999 --count %d --interval %s"
                     % (sender, N, args.interval))
        print(out.strip(), flush=True)
        # 等所有上送到达
        time.sleep(2.0)

        with ctrl.lock:
            pin = ctrl.packetin_count
            dig = ctrl.digest_count
            lat = list(ctrl.packetin_latencies)
            sample_pin = ctrl.packetin_records[0] if ctrl.packetin_records else None
            sample_dig = ctrl.digest_records[0] if ctrl.digest_records else None

        # ---- 数据平面 upload_counter 交叉核对(差值)----
        dp_uploads = read_dp_uploads() - dp_before

        log("数据平面 upload_counter[ingress=1] 增量 = %d(应 = %d)" % (dp_uploads, N))
        log("控制器收到 PacketIn = %d / %d  (%.1f%%)" % (pin, N, 100.0 * pin / N))
        log("控制器收到 Digest   = %d / %d  (%.1f%%)" % (dig, N, 100.0 * dig / N))
        if sample_pin:
            log("PacketIn 样例(metadata)= %s" % sample_pin)
        if sample_dig:
            log("Digest   样例 = %s" % sample_dig)
        if lat:
            log("一路上送延迟(PacketIn,n=%d): 中位 %.2f ms,均值 %.2f ms,max %.2f ms"
                % (len(lat), 1000*statistics.median(lat),
                   1000*statistics.mean(lat), 1000*max(lat)))

        # ---- 反向动作演示 ----
        log("==== 反向动作演示 ====")
        # (1) PacketOut:从控制器回注一个包到出端口 2(-> h2)
        from scapy.all import Ether, IP, UDP, Raw
        probe = Ether(src="08:00:00:00:00:99", dst="08:00:00:00:02:22") / \
            IP(src="10.0.1.1", dst="10.0.2.2") / UDP(sport=1234, dport=4321) / Raw(b"from-controller")
        ctrl.send_packet_out(bytes(probe), egress_port=2)
        log("(1) PacketOut 已回注一个包到端口 2(host->数据平面)")
        # (2) 据上送内容写一条表项(反应式控制):为 h1 方向也加 monitor
        ctrl.add_monitor_entry("10.0.1.1")
        log("(2) 据上送内容写表项:新增 monitor_flows(dst=10.0.1.1)")

        # ---- 判定 ----
        ok_pin = pin >= 0.95 * N
        ok_dig = dig >= 0.95 * N
        ok_dp = dp_uploads == N
        log("判定:PacketIn率%s  Digest率%s  数据面计数一致%s" %
            ("OK" if ok_pin else "FAIL", "OK" if ok_dig else "FAIL",
             "OK" if ok_dp else "FAIL"))
        if ok_pin and ok_dig and ok_dp and ping_loss == "0":
            log("==== 轨道2 上送通道:PASS ====")
            rc = 0
        else:
            log("==== 轨道2 上送通道:FAIL ====")
            rc = 2
    finally:
        if ctrl is not None:
            ctrl.stop_receivers()
            ctrl.shutdown()
        net.stop()
        log("Mininet 已停止")
    sys.exit(rc)


if __name__ == "__main__":
    main()
