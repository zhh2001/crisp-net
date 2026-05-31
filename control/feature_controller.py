#!/usr/bin/env python3
"""
feature_controller.py — CRISP-Net 第 7a 步:在网特征引擎的 host 控制器

P4Runtime:推 pipeline、使能 digest;后台线程持续接收 feature_engine.p4 上送的 Digest,
把每个 W=32 窗口的 33 字段(flow_id + 32 个非零特征)解码为 dict 落入 self.records。
"""
import os
import sys
import threading
from queue import Queue, Empty

TUTORIALS_UTILS = os.path.expanduser("~/tutorials/utils")
sys.path.insert(0, TUTORIALS_UTILS)

import grpc
from p4.v1 import p4runtime_pb2
import p4runtime_lib.switch as p4switch


class _DigestDispatcher:
    def __init__(self, stream):
        self.stream = stream; self.running = True
        self.arbitration_queue = Queue(); self.packet_in_queue = Queue()
        self.timeout_queue = Queue(); self.error_queue = Queue(); self.digest_queue = Queue()
        self.thread = threading.Thread(target=self._loop, daemon=True); self.thread.start()

    def _loop(self):
        try:
            for msg in self.stream:
                if not self.running:
                    break
                if msg.HasField("arbitration"):
                    self.arbitration_queue.put(msg.arbitration)
                elif msg.HasField("digest"):
                    self.digest_queue.put(msg.digest)
                elif msg.HasField("packet"):
                    self.packet_in_queue.put(msg.packet)
                elif msg.HasField("idle_timeout_notification"):
                    self.timeout_queue.put(msg.idle_timeout_notification)
                elif msg.HasField("error"):
                    self.error_queue.put(msg.error)
        except grpc.RpcError:
            pass

    def stop(self):
        self.running = False


p4switch.StreamDispatcher = _DigestDispatcher

import p4runtime_lib.bmv2 as bmv2          # noqa: E402
import p4runtime_lib.helper as p4helper    # noqa: E402

# digest 结构字段顺序(与 feature_engine.p4 的 feat_digest_t 一致)
FIELDS = (["flow_id"] +
          ["len_%d" % i for i in range(1, 9)] +
          ["dir_%d" % i for i in range(1, 9)] +
          ["iat_%d" % i for i in range(2, 9)] +
          ["sum_len", "min_len", "max_len", "n_fwd", "n_bwd", "n_small", "n_large",
           "iat_sum", "iat_max"])


class FeatureController:
    def __init__(self, p4info_path, bmv2_json, address="127.0.0.1:50051", device_id=0,
                 proto_dump_file=None):
        self.helper = p4helper.P4InfoHelper(p4info_path)
        self.bmv2_json = bmv2_json
        self.conn = bmv2.Bmv2SwitchConnection(name="s1", address=address,
                                              device_id=device_id, proto_dump_file=proto_dump_file)
        self.digest_id = self.helper.get_digests_id("feat_digest_t")
        self.lock = threading.Lock()
        self.records = []          # 每条 = {field: int}
        self._running = False
        self._thread = None

    def install_pipeline(self):
        self.conn.MasterArbitrationUpdate()
        self.conn.SetForwardingPipelineConfig(p4info=self.helper.p4info,
                                              bmv2_json_file_path=self.bmv2_json)

    def enable_digest(self, max_list_size=1, max_timeout_ns=0, ack_timeout_ns=0):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.conn.device_id; req.election_id.low = 1
        upd = req.updates.add(); upd.type = p4runtime_pb2.Update.INSERT
        de = upd.entity.digest_entry
        de.digest_id = self.digest_id
        de.config.max_timeout_ns = max_timeout_ns
        de.config.max_list_size = max_list_size
        de.config.ack_timeout_ns = ack_timeout_ns
        self.conn.client_stub.Write(req)

    def _decode(self, digest_list):
        for data in digest_list.data:
            members = data.struct.members
            rec = {}
            for i, m in enumerate(members):
                rec[FIELDS[i]] = int.from_bytes(m.bitstring, "big")
            with self.lock:
                self.records.append(rec)

    def _ack(self, dl):
        req = p4runtime_pb2.StreamMessageRequest()
        req.digest_ack.digest_id = dl.digest_id
        req.digest_ack.list_id = dl.list_id
        self.conn.requests_stream.put(req)

    def _loop(self):
        q = self.conn.dispatcher.digest_queue
        while self._running:
            try:
                dl = q.get(timeout=0.3)
            except Empty:
                continue
            self._decode(dl)
            self._ack(dl)

    def start_receiver(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop_receiver(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def count(self):
        with self.lock:
            return len(self.records)

    def shutdown(self):
        try:
            p4switch.ShutdownAllSwitchConnections()
        except Exception:
            pass
