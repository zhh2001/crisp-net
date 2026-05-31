#!/usr/bin/env python3
"""
probe_sender.py — 在 h1 命名空间内发 N 个 UDP 探针,触发数据平面上送。

每个探针负载内嵌发送时刻(b"CRISPts:" + 8字节 big-endian double),
控制器收到 PacketIn 后据此估算一路上送延迟(同主机同时钟)。
"""
import argparse
import socket
import struct
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", default="10.0.2.2")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--count", type=int, default=120)
    ap.add_argument("--interval", type=float, default=0.02)
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for i in range(args.count):
        payload = b"CRISPts:" + struct.pack(">d", time.time()) + (" seq=%d" % i).encode()
        try:
            s.sendto(payload, (args.dst, args.port))
            sent += 1
        except OSError:
            pass
        time.sleep(args.interval)
    print("probe_sender: sent %d/%d UDP probes to %s:%d" %
          (sent, args.count, args.dst, args.port))


if __name__ == "__main__":
    main()
