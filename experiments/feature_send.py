#!/usr/bin/env python3
"""
feature_send.py — 在 h1 命名空间内,按 spec 把 QUIC 测试流合成报文并 L2 直发到交换机。

spec(npz):flows = 列表,每条 = (srcport, sizes[], dirbits[], iat_us[])。
每包:Ether/IP/UDP/驱动头(dir,iat_us,seq)/pad,使 ipv4.totalLen == size(真实包长)。
按流顺序发送(保持 per-flow 包序);iat 由头携带,不依赖发送时序。
"""
import argparse
import struct
import numpy as np
from scapy.all import Ether, IP, UDP, Raw, sendp

H1_MAC = "08:00:00:00:01:11"
H2_MAC = "08:00:00:00:02:22"
H1_IP = "10.0.1.1"
H2_IP = "10.0.2.2"
DPORT = 9999


def build_flow_pkts(srcport, sizes, dirbits, iat_us):
    pkts = []
    for seq, (sz, db, iu) in enumerate(zip(sizes, dirbits, iat_us)):
        sz = int(sz)
        padlen = max(0, sz - 40)              # 20 IP + 8 UDP + 12 drv = 40
        drv = struct.pack(">HHIHH", int(db), 0, int(iu), seq & 0xffff, 0)
        payload = drv + (b"\x00" * padlen)
        pkt = (Ether(src=H1_MAC, dst=H2_MAC) /
               IP(src=H1_IP, dst=H2_IP) /
               UDP(sport=int(srcport), dport=DPORT) /
               Raw(payload))
        pkts.append(pkt)
    return pkts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--iface", default="h1-eth0")
    args = ap.parse_args()
    d = np.load(args.spec, allow_pickle=True)
    flows = d["flows"]
    total = 0
    for f in flows:
        srcport, sizes, dirbits, iat_us = f
        pkts = build_flow_pkts(srcport, sizes, dirbits, iat_us)
        sendp(pkts, iface=args.iface, verbose=False)
        total += len(pkts)
    print("feature_send: sent %d packets across %d flows" % (total, len(flows)))


if __name__ == "__main__":
    main()
