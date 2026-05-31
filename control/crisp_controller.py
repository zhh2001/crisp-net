#!/usr/bin/env python3
"""
crisp_controller.py — CRISP-Net 第 2 步 / 轨道 2:host 侧 P4Runtime 控制器

职责:
  - 打开 P4Runtime StreamChannel,推 pipeline、配 clone session、使能 digest;
  - 灌入正常转发表 (ipv4_lpm) 与 monitor_flows(决定哪些流上送);
  - 持续接收两类上送并记录/计数:
      * PacketIn(整包拷贝,流特征在 controller_header -> PacketIn.metadata)
      * Digest  (小结构体 flow_digest_t,经 DigestList)
  - 演示"反向动作":对收到的上送回注一个 PacketOut(指定出端口),
    并可据上送内容写一条表项(此处用 monitor_flows 示例)。

依赖 tutorials/utils/p4runtime_lib(helper 建表项、bmv2 连接);
为接收 digest,monkeypatch 了它的 StreamDispatcher 以增加 digest 队列。

可独立运行(连已起的 simple_switch_grpc):
    sudo -E python3 control/crisp_controller.py --p4info ... --bmv2-json ... --serve
"""
import os
import sys
import time
import struct
import threading
from queue import Queue, Empty

TUTORIALS_UTILS = os.path.expanduser("~/tutorials/utils")
sys.path.insert(0, TUTORIALS_UTILS)

import grpc
from p4.v1 import p4runtime_pb2
import p4runtime_lib.switch as p4switch


# ---- 扩展 StreamDispatcher:在原有 packet_in 之外增加 digest 队列 ----
class _ExtendedStreamDispatcher:
    def __init__(self, stream):
        self.stream = stream
        self.running = True
        self.arbitration_queue = Queue()
        self.packet_in_queue = Queue()
        self.timeout_queue = Queue()
        self.error_queue = Queue()
        self.digest_queue = Queue()          # 新增
        self.thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self.thread.start()

    def _dispatch_loop(self):
        try:
            for msg in self.stream:
                if not self.running:
                    break
                if msg.HasField("arbitration"):
                    self.arbitration_queue.put(msg.arbitration)
                elif msg.HasField("packet"):
                    self.packet_in_queue.put(msg.packet)
                elif msg.HasField("digest"):
                    self.digest_queue.put(msg.digest)
                elif msg.HasField("idle_timeout_notification"):
                    self.timeout_queue.put(msg.idle_timeout_notification)
                elif msg.HasField("error"):
                    self.error_queue.put(msg.error)
        except grpc.RpcError:
            pass

    def stop(self):
        self.running = False


# 必须在创建连接之前打补丁
p4switch.StreamDispatcher = _ExtendedStreamDispatcher

import p4runtime_lib.bmv2 as bmv2          # noqa: E402
import p4runtime_lib.helper as p4helper    # noqa: E402


CPU_PORT = 510
CPU_PORT_CLONE_SESSION_ID = 57


class CrispUploadController:
    def __init__(self, p4info_path, bmv2_json_path,
                 address="127.0.0.1:50051", device_id=0,
                 proto_dump_file=None):
        self.helper = p4helper.P4InfoHelper(p4info_path)
        self.bmv2_json = bmv2_json_path
        self.conn = bmv2.Bmv2SwitchConnection(
            name="s1", address=address, device_id=device_id,
            proto_dump_file=proto_dump_file)
        self.digest_id = self.helper.get_digests_id("flow_digest_t")
        self.pktin_md = self._packetin_metadata_layout()

        # 统计与记录
        self.lock = threading.Lock()
        self.packetin_count = 0
        self.digest_count = 0
        self.packetin_records = []
        self.digest_records = []
        self.packetin_latencies = []     # 一路单向延迟(payload 内嵌时间戳)
        self._running = False
        self._threads = []

    # ---------- 初始化数据平面 ----------
    def install_pipeline(self):
        self.conn.MasterArbitrationUpdate()
        self.conn.SetForwardingPipelineConfig(
            p4info=self.helper.p4info, bmv2_json_file_path=self.bmv2_json)

    def add_clone_session(self):
        """配置 clone session -> CPU_PORT,供 PacketIn(clone I2E)使用。"""
        replicas = [{"egress_port": CPU_PORT, "instance": 1}]
        entry = self.helper.buildCloneSessionEntry(
            CPU_PORT_CLONE_SESSION_ID, replicas, 0)
        self.conn.WritePREEntry(entry)

    def enable_digest(self, max_list_size=1, max_timeout_ns=0, ack_timeout_ns=0):
        """使能 digest 投递(max_list_size=1 -> 每条 DigestList 一个记录,便于计数)。"""
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.conn.device_id
        req.election_id.low = 1
        upd = req.updates.add()
        upd.type = p4runtime_pb2.Update.INSERT
        de = upd.entity.digest_entry
        de.digest_id = self.digest_id
        de.config.max_timeout_ns = max_timeout_ns
        de.config.max_list_size = max_list_size
        de.config.ack_timeout_ns = ack_timeout_ns
        self.conn.client_stub.Write(req)

    def add_forward_entry(self, dst_ip, dst_mac, port):
        self.conn.WriteTableEntry(self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": dst_mac, "port": port}))

    def add_default_drop(self):
        self.conn.WriteTableEntry(self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            default_action=True, action_name="MyIngress.drop", action_params={}))

    def add_monitor_entry(self, dst_ip, prefix=32):
        """标记 dst_ip 的流为"需上送"。"""
        self.conn.WriteTableEntry(self.helper.buildTableEntry(
            table_name="MyIngress.monitor_flows",
            match_fields={"hdr.ipv4.dstAddr": (dst_ip, prefix)},
            action_name="MyIngress.mark_upload", action_params={}))

    # ---------- 接收上送 ----------
    def _packetin_metadata_layout(self):
        for c in self.helper.p4info.controller_packet_metadata:
            if c.preamble.name == "packet_in":
                return {m.id: (m.name, m.bitwidth) for m in c.metadata}
        return {}

    def _decode_packetin(self, pkt):
        md = {}
        for m in pkt.metadata:
            name, _bw = self.pktin_md.get(m.metadata_id, (str(m.metadata_id), 0))
            md[name] = int.from_bytes(m.value, "big")
        # payload = 原始以太帧(含我们在 h1 端嵌入时间戳的 UDP 负载)
        latency = self._extract_latency(pkt.payload)
        return md, latency

    @staticmethod
    def _extract_latency(payload):
        """探针 UDP 负载里嵌了发送时刻(8字节 double, big-endian),用于估一路延迟。"""
        marker = b"CRISPts:"
        idx = payload.find(marker)
        if idx < 0 or idx + len(marker) + 8 > len(payload):
            return None
        t_send = struct.unpack(">d", payload[idx + len(marker): idx + len(marker) + 8])[0]
        return max(0.0, time.time() - t_send)

    def _decode_digest(self, digest_list):
        """flow_digest_t 字段顺序:ingress_port,protocol,src_addr,dst_addr,src_port,dst_port,pkt_len"""
        names = ["ingress_port", "protocol", "src_addr", "dst_addr",
                 "src_port", "dst_port", "pkt_len"]
        out = []
        for data in digest_list.data:
            members = data.struct.members
            rec = {}
            for i, m in enumerate(members):
                rec[names[i] if i < len(names) else str(i)] = int.from_bytes(m.bitstring, "big")
            out.append(rec)
        return out

    def _ack_digest(self, digest_list):
        req = p4runtime_pb2.StreamMessageRequest()
        req.digest_ack.digest_id = digest_list.digest_id
        req.digest_ack.list_id = digest_list.list_id
        self.conn.requests_stream.put(req)

    def _packetin_loop(self):
        q = self.conn.dispatcher.packet_in_queue
        while self._running:
            try:
                pkt = q.get(timeout=0.3)
            except Empty:
                continue
            md, latency = self._decode_packetin(pkt)
            with self.lock:
                self.packetin_count += 1
                self.packetin_records.append(md)
                if latency is not None:
                    self.packetin_latencies.append(latency)

    def _digest_loop(self):
        q = self.conn.dispatcher.digest_queue
        while self._running:
            try:
                dl = q.get(timeout=0.3)
            except Empty:
                continue
            recs = self._decode_digest(dl)
            self._ack_digest(dl)
            with self.lock:
                self.digest_count += len(recs)
                self.digest_records.extend(recs)

    def start_receivers(self):
        self._running = True
        self._threads = [
            threading.Thread(target=self._packetin_loop, daemon=True),
            threading.Thread(target=self._digest_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    def stop_receivers(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=1.0)

    # ---------- 反向动作 ----------
    def send_packet_out(self, raw_payload, egress_port):
        """把一个包从控制器回注到指定出端口(演示 host -> 数据平面)。"""
        metadatas = [{"value": egress_port, "bitwidth": 16},
                     {"value": 0, "bitwidth": 16}]  # egress_port, pad
        self.conn.PacketOut(raw_payload, metadatas)

    def shutdown(self):
        try:
            p4switch.ShutdownAllSwitchConnections()
        except Exception:
            pass


def _serve_main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4info", required=True)
    ap.add_argument("--bmv2-json", required=True)
    ap.add_argument("--address", default="127.0.0.1:50051")
    ap.add_argument("--monitor-ip", default="10.0.2.2")
    ap.add_argument("--serve", action="store_true", help="持续打印收到的上送,Ctrl-C 退出")
    args = ap.parse_args()

    c = CrispUploadController(args.p4info, args.bmv2_json, address=args.address)
    c.install_pipeline()
    c.add_clone_session()
    c.enable_digest()
    c.add_default_drop()
    c.add_forward_entry("10.0.1.1", "08:00:00:00:01:11", 1)
    c.add_forward_entry("10.0.2.2", "08:00:00:00:02:22", 2)
    c.add_monitor_entry(args.monitor_ip)
    c.start_receivers()
    print("[controller] 已就绪:pipeline/clone/digest/表项已装载,监控 dst=%s" % args.monitor_ip)
    print("[controller] 持续接收 PacketIn / Digest ... Ctrl-C 退出")
    try:
        while True:
            time.sleep(1.0)
            with c.lock:
                print("[controller] PacketIn=%d  Digest=%d" %
                      (c.packetin_count, c.digest_count))
    except KeyboardInterrupt:
        print("\n[controller] 退出")
    finally:
        c.stop_receivers()
        c.shutdown()


if __name__ == "__main__":
    _serve_main()
