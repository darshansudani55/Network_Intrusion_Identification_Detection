"""
Signature / Rule-Based Detection Engine
----------------------------------------
Fast, deterministic threshold checks. Low false-positive rate by design.
This is the "signature-based" half of the hybrid system.
"""

from dataclasses import dataclass
from typing import Optional
from app.features.flow_extractor import Flow, FlowTracker


@dataclass
class RuleVerdict:
    triggered: bool
    attack_type: Optional[str]
    reason: str
    confidence: float  # 0-1, rule-based confidence (deterministic, usually 1.0 or 0.0)


# ---- Tunable thresholds -----------------------------------------------
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 15   # distinct ports in SCAN_WINDOW seconds
SYN_FLOOD_PPS_THRESHOLD = 150            # packets/sec on a single flow
SYN_ACK_RATIO_THRESHOLD = 5.0            # SYN sent but few ACKs completed
GENERIC_DOS_PPS_THRESHOLD = 300          # raw packet rate, any protocol
SLOW_DOS_MIN_DURATION = 30.0             # seconds; long-lived low-rate = slowloris-style
SLOW_DOS_MAX_PPS = 2.0
# ------------------------------------------------------------------------


class RuleEngine:
    def __init__(self, tracker: FlowTracker):
        self.tracker = tracker

    def check_port_scan(self, flow: Flow) -> RuleVerdict:
        distinct = self.tracker.distinct_ports_touched(flow.src_ip)
        if distinct >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            # Heuristic sub-classification by flag pattern
            if flow.syn_count > 0 and flow.ack_count == 0:
                scan_type = "SYN Scan (half-open)"
            elif flow.fin_count > 0 and flow.syn_count == 0:
                scan_type = "FIN Scan"
            elif flow.syn_count == 0 and flow.fin_count == 0 and flow.ack_count == 0:
                scan_type = "NULL Scan"
            else:
                scan_type = "Generic Port Scan"
            return RuleVerdict(
                triggered=True,
                attack_type=f"PortScan:{scan_type}",
                reason=f"{flow.src_ip} touched {distinct} distinct ports in "
                       f"the last scan window (threshold={PORT_SCAN_DISTINCT_PORT_THRESHOLD})",
                confidence=1.0,
            )
        return RuleVerdict(False, None, "", 0.0)

    def check_dos(self, flow: Flow) -> RuleVerdict:
        pps = flow.total_packets / flow.duration

        # SYN flood: high SYN rate, disproportionate to completed handshakes
        if flow.syn_count >= 20 and (flow.syn_count / (flow.ack_count + 1)) >= SYN_ACK_RATIO_THRESHOLD \
                and pps >= SYN_FLOOD_PPS_THRESHOLD * 0.3:
            return RuleVerdict(
                True, "DoS:SYN Flood",
                f"SYN/ACK ratio {flow.syn_count}/{flow.ack_count + 1} with {pps:.1f} pkt/s "
                f"from {flow.src_ip}",
                confidence=1.0,
            )

        # Generic volumetric flood
        if pps >= GENERIC_DOS_PPS_THRESHOLD:
            return RuleVerdict(
                True, "DoS:Volumetric Flood",
                f"{pps:.1f} packets/sec on single flow from {flow.src_ip} "
                f"(threshold={GENERIC_DOS_PPS_THRESHOLD})",
                confidence=1.0,
            )

        # Slow DoS (Slowloris / Slowhttptest style): long duration, trickle rate,
        # many half-open / PSH-heavy connections
        if flow.duration >= SLOW_DOS_MIN_DURATION and pps <= SLOW_DOS_MAX_PPS \
                and flow.psh_count >= 5:
            return RuleVerdict(
                True, "DoS:Slow Rate (Slowloris-style)",
                f"Long-lived low-rate connection ({flow.duration:.0f}s, {pps:.2f} pkt/s) "
                f"with repeated partial requests from {flow.src_ip}",
                confidence=0.85,
            )

        return RuleVerdict(False, None, "", 0.0)

    def evaluate(self, flow: Flow) -> list[RuleVerdict]:
        verdicts = []
        v1 = self.check_port_scan(flow)
        if v1.triggered:
            verdicts.append(v1)
        v2 = self.check_dos(flow)
        if v2.triggered:
            verdicts.append(v2)
        return verdicts
