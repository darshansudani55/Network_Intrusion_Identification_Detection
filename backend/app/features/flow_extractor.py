"""
Flow Feature Extractor
-----------------------
Groups raw packets into bidirectional flows (5-tuple: src_ip, dst_ip, src_port,
dst_port, protocol) and computes CICIDS2017-style statistical features used by
both the rule engine and the ML model.

Works with:
  - Live capture (Scapy sniff callback)
  - Offline pcap replay
  - Synthetic packet dicts (for testing without real traffic)
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Optional


FLOW_TIMEOUT = 5.0   # seconds of inactivity before a flow is considered closed
SCAN_WINDOW = 10.0    # sliding window (seconds) used for port-scan tracking


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    packet_lengths: List[int] = field(default_factory=list)
    iat_list: List[float] = field(default_factory=list)  # inter-arrival times

    def add_packet(self, direction: str, length: int, flags: Dict[str, bool], ts: float):
        if self.packet_lengths:
            self.iat_list.append(ts - self.last_seen)
        self.last_seen = ts

        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length

        self.packet_lengths.append(length)

        if flags.get("SYN"):
            self.syn_count += 1
        if flags.get("ACK"):
            self.ack_count += 1
        if flags.get("FIN"):
            self.fin_count += 1
        if flags.get("RST"):
            self.rst_count += 1
        if flags.get("PSH"):
            self.psh_count += 1
        if flags.get("URG"):
            self.urg_count += 1

    @property
    def duration(self) -> float:
        # Floor at 1ms so single/near-instant packets don't produce absurd
        # pps values (e.g. 1 packet / 1e-6s = 1,000,000 pkt/s). A scan probe
        # is still "fast" at a realistic ~1000 pkt/s ceiling, which is what
        # actually trips the volumetric threshold rather than a divide-by-
        # near-zero artifact.
        return max(self.last_seen - self.start_time, 1e-3)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    def to_feature_dict(self) -> dict:
        """Produces the feature vector consumed by the ML model + rule engine."""
        n = len(self.packet_lengths)
        avg_len = sum(self.packet_lengths) / n if n else 0.0
        max_len = max(self.packet_lengths) if n else 0
        min_len = min(self.packet_lengths) if n else 0

        avg_iat = sum(self.iat_list) / len(self.iat_list) if self.iat_list else 0.0

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": self.duration,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "packets_per_sec": self.total_packets / self.duration,
            "bytes_per_sec": self.total_bytes / self.duration,
            "avg_packet_size": avg_len,
            "max_packet_size": max_len,
            "min_packet_size": min_len,
            "avg_iat": avg_iat,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "urg_count": self.urg_count,
            "syn_ack_ratio": self.syn_count / (self.ack_count + 1),
            "fwd_bwd_ratio": self.fwd_packets / (self.bwd_packets + 1),
        }


class FlowTracker:
    """
    Maintains active flows and per-source-IP destination-port history
    (needed for port-scan detection independent of any single flow).
    """

    def __init__(self):
        self.flows: Dict[tuple, Flow] = {}
        # src_ip -> list of (timestamp, dst_ip, dst_port)
        self.port_touches: Dict[str, List[tuple]] = defaultdict(list)

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Unordered key so both directions of a conversation map to the same
        # flow entry, regardless of which side we saw first.
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        return tuple(sorted([a, b])) + (protocol,)

    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                        protocol: str, length: int, flags: Optional[Dict[str, bool]] = None,
                        ts: Optional[float] = None) -> Flow:
        ts = ts or time.time()
        flags = flags or {}

        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        if key not in self.flows:
            # The flow initiator (this packet's src) is fixed as the flow's
            # canonical src_ip/dst_ip for the life of the flow, so rule
            # checks (e.g. "which IP is scanning") stay attributed correctly
            # regardless of which side happens to sort first/second.
            self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self.flows[key]
        direction = "fwd" if (src_ip, src_port) == (flow.src_ip, flow.src_port) else "bwd"
        flow.add_packet(direction, length, flags, ts)

        # Track for port-scan detection
        self.port_touches[src_ip].append((ts, dst_ip, dst_port))
        self._prune_port_touches(src_ip, ts)

        return flow

    def _prune_port_touches(self, src_ip: str, now: float):
        cutoff = now - SCAN_WINDOW
        self.port_touches[src_ip] = [
            t for t in self.port_touches[src_ip] if t[0] >= cutoff
        ]

    def distinct_ports_touched(self, src_ip: str) -> int:
        return len({(d[1], d[2]) for d in self.port_touches[src_ip]})

    def expire_flows(self, now: Optional[float] = None) -> List[Flow]:
        """Return and remove flows that have been idle past FLOW_TIMEOUT."""
        now = now or time.time()
        expired = []
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if now - flow.last_seen > FLOW_TIMEOUT:
                expired.append(flow)
                del self.flows[key]
        return expired

    def active_flows(self) -> List[Flow]:
        return list(self.flows.values())
