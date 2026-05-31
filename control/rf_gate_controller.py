#!/usr/bin/env python3
"""
rf_gate_controller.py — CRISP-Net 第 7b 步控制器:灌 RF/LUT 表项 + 写 τ 寄存器 + 收决策 Digest

读 data/processed/quic/rf_entries.json:把 10 棵树的叶子作 range 表项灌入 tree_0..9,
把 isotonic LUT 作 range 表项灌入 isotonic_lut,把 τ8 写入 r_tau 寄存器,使能 digest;
后台线程接收 dec_digest_t (flow_id, pred, score, calib8, accept) 落 self.records。
"""
import os
import sys
import json
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
                elif msg.HasField("error"):
                    self.error_queue.put(msg.error)
        except grpc.RpcError:
            pass

    def stop(self):
        self.running = False


p4switch.StreamDispatcher = _DigestDispatcher
import p4runtime_lib.bmv2 as bmv2          # noqa: E402
import p4runtime_lib.helper as p4helper    # noqa: E402

DEC_FIELDS = ["flow_id", "pred", "score", "calib8", "accept"]


class RFGateController:
    def __init__(self, p4info, bmv2_json, entries_path, address="127.0.0.1:50051",
                 device_id=0, proto_dump_file=None):
        self.helper = p4helper.P4InfoHelper(p4info)
        self.bmv2_json = bmv2_json
        self.entries = json.load(open(entries_path))
        self.conn = bmv2.Bmv2SwitchConnection(name="s1", address=address,
                                              device_id=device_id, proto_dump_file=proto_dump_file)
        self.digest_id = self.helper.get_digests_id("dec_digest_t")
        self.lock = threading.Lock(); self.records = []
        self._running = False; self._thread = None

    def install_pipeline(self):
        self.conn.MasterArbitrationUpdate()
        self.conn.SetForwardingPipelineConfig(p4info=self.helper.p4info,
                                              bmv2_json_file_path=self.bmv2_json)

    def _batch_write(self, table_entries, batch=120):
        for i in range(0, len(table_entries), batch):
            req = p4runtime_pb2.WriteRequest()
            req.device_id = self.conn.device_id; req.election_id.low = 1
            for te in table_entries[i:i + batch]:
                upd = req.updates.add(); upd.type = p4runtime_pb2.Update.INSERT
                upd.entity.table_entry.CopyFrom(te)
            self.conn.client_stub.Write(req)

    def install_entries(self):
        kf = self.entries["key_feats"]
        n_inserted = 0
        for ti, tree in enumerate(self.entries["trees"]):
            tes = []
            for e in tree:
                match = {("meta.f_%s" % f): (v[0], v[1]) for f, v in e["match"].items()}
                params = {("p%d" % j): int(e["params"][j]) for j in range(5)}
                te = self.helper.buildTableEntry(
                    table_name="MyIngress.tree_%d" % ti,
                    match_fields=match if match else None,
                    action_name="MyIngress.add_leaf", action_params=params,
                    priority=int(e["prio"]))
                tes.append(te)
            self._batch_write(tes); n_inserted += len(tes)
        # isotonic LUT
        tes = []
        for seg in self.entries["lut"]:
            te = self.helper.buildTableEntry(
                table_name="MyIngress.isotonic_lut",
                match_fields={"meta.score": (seg["lo"], seg["hi"])},
                action_name="MyIngress.set_calib", action_params={"c": int(seg["calib"])},
                priority=int(seg["prio"]))
            tes.append(te)
        self._batch_write(tes); n_inserted += len(tes)
        return n_inserted

    def write_tau(self):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.conn.device_id; req.election_id.low = 1
        upd = req.updates.add(); upd.type = p4runtime_pb2.Update.MODIFY
        re = upd.entity.register_entry
        re.register_id = self.helper.get_registers_id("r_tau")
        re.index.index = 0
        re.data.bitstring = int(self.entries["tau8"]).to_bytes(4, "big")
        self.conn.client_stub.Write(req)

    def enable_digest(self, max_list_size=1):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.conn.device_id; req.election_id.low = 1
        upd = req.updates.add(); upd.type = p4runtime_pb2.Update.INSERT
        de = upd.entity.digest_entry
        de.digest_id = self.digest_id
        de.config.max_timeout_ns = 0; de.config.max_list_size = max_list_size; de.config.ack_timeout_ns = 0
        self.conn.client_stub.Write(req)

    def _loop(self):
        q = self.conn.dispatcher.digest_queue
        while self._running:
            try:
                dl = q.get(timeout=0.3)
            except Empty:
                continue
            for data in dl.data:
                rec = {DEC_FIELDS[i]: int.from_bytes(m.bitstring, "big")
                       for i, m in enumerate(data.struct.members)}
                with self.lock:
                    self.records.append(rec)
            ack = p4runtime_pb2.StreamMessageRequest()
            ack.digest_ack.digest_id = dl.digest_id; ack.digest_ack.list_id = dl.list_id
            self.conn.requests_stream.put(ack)

    def start_receiver(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True); self._thread.start()

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
