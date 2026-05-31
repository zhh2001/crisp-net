#!/usr/bin/env python3
"""
upload_topo.py — CRISP-Net 第 2 步 / 轨道 2 拓扑

1 台 BMv2 交换机 (s1, simple_switch_grpc, --cpu-port 510) + 2 主机 (h1, h2)。

    h1 (10.0.1.1/24) --- s1-p1   [s1]   s1-p2 --- h2 (10.0.2.2/24)

与轨道 1 步骤一同套的 L3 配置(不同 /24,默认网关 + 静态 ARP,关 IPv6 噪声)。
交换机以 --no-p4 启动,程序/表项经 P4Runtime 由 crisp_controller 推入。
"""
from mininet.topo import Topo

HOSTS = {
    "h1": dict(ip="10.0.1.1/24", mac="08:00:00:00:01:11",
               gw="10.0.1.10", gw_mac="08:00:00:00:01:00", port=1),
    "h2": dict(ip="10.0.2.2/24", mac="08:00:00:00:02:22",
               gw="10.0.2.20", gw_mac="08:00:00:00:02:00", port=2),
}

CPU_PORT = 510


class UploadTopo(Topo):
    def __init__(self, sw_path=None, grpc_port=50051, thrift_port=9090,
                 log_file=None, log_console=False, **kwargs):
        Topo.__init__(self, **kwargs)
        s1 = self.addSwitch(
            "s1",
            sw_path=sw_path,
            json_path=None,            # --no-p4,程序经 P4Runtime 推入
            grpc_port=grpc_port,
            thrift_port=thrift_port,
            cpu_port=CPU_PORT,         # PacketIn/PacketOut 的 CPU 端口
            log_file=log_file,
            log_console=log_console,
        )
        for name in ("h1", "h2"):
            h = HOSTS[name]
            host = self.addHost(name, ip=h["ip"], mac=h["mac"])
            self.addLink(host, s1, port2=h["port"])


def configure_hosts(net, verbose=False):
    for name, h in HOSTS.items():
        host = net.get(name)
        intf = "{}-eth0".format(name)
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("ip route add default via {} dev {}".format(h["gw"], intf))
        host.cmd("arp -i {} -s {} {}".format(intf, h["gw"], h["gw_mac"]))
        if verbose:
            print("---- {} ----".format(name), flush=True)
            print(host.cmd("ip -4 addr show {} | grep inet".format(intf)), flush=True)
