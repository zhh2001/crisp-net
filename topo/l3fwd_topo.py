#!/usr/bin/env python3
"""
l3fwd_topo.py — CRISP-Net 第 1 步「自有工作流关」拓扑

最小拓扑:1 台 BMv2 交换机 (s1) + 2 台主机 (h1, h2)。

    h1 (10.0.1.1/24) --- s1-p1   [s1: simple_switch_grpc]   s1-p2 --- h2 (10.0.2.2/24)

两台主机分属不同 /24 子网,通过 s1 做 L3(IPv4 LPM)转发 —— 真正走数据面的
ipv4_lpm 表,而非二层桥接。每台主机设默认网关 + 静态 ARP(指向 s1 的虚拟网关 MAC),
与 p4lang/tutorials 的 basic 练习同套配置约定。

交换机使用 tutorials/utils 提供的 P4RuntimeSwitch(以 --no-p4 启动,程序与表项
随后经 P4Runtime 推入),因此本文件依赖 tutorials/utils 在 sys.path 中。
"""

from mininet.topo import Topo

# 主机定义:名字 -> (IP/前缀, MAC, 默认网关, 网关 MAC, 交换机端口号)
HOSTS = {
    "h1": dict(ip="10.0.1.1/24", mac="08:00:00:00:01:11",
               gw="10.0.1.10", gw_mac="08:00:00:00:01:00", port=1),
    "h2": dict(ip="10.0.2.2/24", mac="08:00:00:00:02:22",
               gw="10.0.2.20", gw_mac="08:00:00:00:02:00", port=2),
}


class L3FwdTopo(Topo):
    """单交换机双主机 L3 转发拓扑。"""

    def __init__(self, sw_path=None, grpc_port=50051, thrift_port=9090,
                 log_file=None, log_console=False, **kwargs):
        Topo.__init__(self, **kwargs)

        s1 = self.addSwitch(
            "s1",
            sw_path=sw_path,
            json_path=None,          # --no-p4:程序经 P4Runtime 推入
            grpc_port=grpc_port,
            thrift_port=thrift_port,
            log_file=log_file,
            log_console=log_console,
        )

        for name in ("h1", "h2"):
            h = HOSTS[name]
            host = self.addHost(name, ip=h["ip"], mac=h["mac"])
            self.addLink(host, s1, port2=h["port"])


def configure_hosts(net, verbose=False):
    """对每台主机设默认网关 + 静态 ARP(在 net.start() 之后调用)。"""
    for name, h in HOSTS.items():
        host = net.get(name)
        intf = "{}-eth0".format(name)
        # 关掉 IPv6,避免 link-local 噪声包淹没交换机日志
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        # 默认路由 + 静态 ARP(网关 = 交换机虚拟网关,MAC 为约定值)
        host.cmd("ip route add default via {} dev {}".format(h["gw"], intf))
        host.cmd("arp -i {} -s {} {}".format(intf, h["gw"], h["gw_mac"]))
        if verbose:
            print("---- {} ip route ----".format(name), flush=True)
            print(host.cmd("ip route"), flush=True)
            print("---- {} arp -n ----".format(name), flush=True)
            print(host.cmd("arp -n"), flush=True)
