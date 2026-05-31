#!/usr/bin/env python3
"""
rf_gate_cl_controller.py — CRISP-Net 第 7c 步控制器:RF 门控闭环
灌 RF/LUT 表项;使能两类 digest:dec_digest_t(每窗口决策)与 seq_digest_t(仅 defer 上送 32 包序列);
后台接收并分别落 self.dec / self.seq。
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


class _DD:
    def __init__(self, stream):
        self.stream = stream; self.running = True
        self.arbitration_queue = Queue(); self.digest_queue = Queue()
        self.packet_in_queue = Queue(); self.error_queue = Queue()
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
        except grpc.RpcError:
            pass

    def stop(self):
        self.running = False


p4switch.StreamDispatcher = _DD
import p4runtime_lib.bmv2 as bmv2          # noqa: E402
import p4runtime_lib.helper as p4helper    # noqa: E402

DEC_FIELDS = ["flow_id", "pred", "score", "calib8", "accept"]
SEQ_FIELDS = (["flow_id"] + ["slen_%d" % i for i in range(1, 33)] +
              ["sdir_%d" % i for i in range(1, 33)] + ["siat_%d" % i for i in range(1, 33)])


class RFGateCLController:
    def __init__(self, p4info, bmv2_json, entries_path, address="127.0.0.1:50051",
                 device_id=0, proto_dump_file=None):
        self.helper = p4helper.P4InfoHelper(p4info)
        self.bmv2_json = bmv2_json
        self.entries = json.load(open(entries_path))
        self.conn = bmv2.Bmv2SwitchConnection(name="s1", address=address,
                                              device_id=device_id, proto_dump_file=proto_dump_file)
        self.id_dec = self.helper.get_digests_id("dec_digest_t")
        self.id_seq = self.helper.get_digests_id("seq_digest_t")
        self.lock = threading.Lock(); self.dec = []; self.seq = []
        self._running = False; self._thread = None

    def install_pipeline(self):
        self.conn.MasterArbitrationUpdate()
        self.conn.SetForwardingPipelineConfig(p4info=self.helper.p4info, bmv2_json_file_path=self.bmv2_json)

    def _bw(self, tes, batch=120):
        for i in range(0, len(tes), batch):
            req = p4runtime_pb2.WriteRequest(); req.device_id = self.conn.device_id; req.election_id.low = 1
            for te in tes[i:i + batch]:
                upd = req.updates.add(); upd.type = p4runtime_pb2.Update.INSERT
                upd.entity.table_entry.CopyFrom(te)
            self.conn.client_stub.Write(req)

    def install_entries(self):
        n = 0
        for ti, tree in enumerate(self.entries["trees"]):
            tes = []
            for e in tree:
                match = {("meta.f_%s" % f): (v[0], v[1]) for f, v in e["match"].items()}
                params = {("p%d" % j): int(e["params"][j]) for j in range(5)}
                tes.append(self.helper.buildTableEntry(
                    table_name="MyIngress.tree_%d" % ti, match_fields=match if match else None,
                    action_name="MyIngress.add_leaf", action_params=params, priority=int(e["prio"])))
            self._bw(tes); n += len(tes)
        tes = []
        for seg in self.entries["lut"]:
            tes.append(self.helper.buildTableEntry(
                table_name="MyIngress.isotonic_lut", match_fields={"meta.score": (seg["lo"], seg["hi"])},
                action_name="MyIngress.set_calib", action_params={"c": int(seg["calib"])}, priority=int(seg["prio"])))
        self._bw(tes); n += len(tes)
        return n

    def _enable(self, did):
        req = p4runtime_pb2.WriteRequest(); req.device_id = self.conn.device_id; req.election_id.low = 1
        upd = req.updates.add(); upd.type = p4runtime_pb2.Update.INSERT
        de = upd.entity.digest_entry; de.digest_id = did
        de.config.max_timeout_ns = 0; de.config.max_list_size = 1; de.config.ack_timeout_ns = 0
        self.conn.client_stub.Write(req)

    def enable_digests(self):
        self._enable(self.id_dec); self._enable(self.id_seq)

    def _loop(self):
        q = self.conn.dispatcher.digest_queue
        while self._running:
            try:
                dl = q.get(timeout=0.3)
            except Empty:
                continue
            fields = DEC_FIELDS if dl.digest_id == self.id_dec else SEQ_FIELDS
            tgt = self.dec if dl.digest_id == self.id_dec else self.seq
            for data in dl.data:
                rec = {fields[i]: int.from_bytes(m.bitstring, "big") for i, m in enumerate(data.struct.members)}
                with self.lock:
                    tgt.append(rec)
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

    def counts(self):
        with self.lock:
            return len(self.dec), len(self.seq)

    def shutdown(self):
        try:
            p4switch.ShutdownAllSwitchConnections()
        except Exception:
            pass
