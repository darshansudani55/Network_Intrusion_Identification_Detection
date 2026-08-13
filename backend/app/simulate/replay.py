"""
Traffic Simulator (Demo Mode)
--------------------------------
Generates synthetic packet streams representing BENIGN, PORT SCAN, and DOS
traffic patterns, and feeds them through the HybridDetector in real time.

This is what powers the live dashboard demo without needing root privileges,
a live network interface, or the real CICIDS2017 pcaps on hand. It's also
what you'd run during your viva to show the system responding to an attack
starting and stopping live.

Attack scenarios are injected on a schedule (see `SCENARIO_SCHEDULE`), so the
dashboard shows periods of normal traffic interrupted by scans/floods -
useful for demonstrating detection latency.
"""

import asyncio
import random
import time
import ipaddress
from app.detection.hybrid import HybridDetector, Alert

BENIGN_IPS = [f"10.0.0.{i}" for i in range(2, 30)]
SERVER_IP = "10.0.0.1"
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.77"]

COMMON_PORTS = [80, 443, 22, 21, 3306, 8080, 25, 53]


def _rand_ip_pool(n=20):
    return [str(ipaddress.IPv4Address(random.randint(0x0B000000, 0x0BFFFFFF))) for _ in range(n)]


class TrafficSimulator:
    def __init__(self, detector: HybridDetector, on_alert=None, on_stat=None):
        self.detector = detector
        self.on_alert = on_alert
        self.on_stat = on_stat  # callback for periodic stats (pps, active flows, etc.)
        self.mode = "benign"     # benign | portscan | dos_volumetric | dos_slow
        self.running = False
        self._packet_count = 0

    def set_mode(self, mode: str):
        assert mode in ("benign", "portscan", "dos_volumetric", "dos_slow")
        self.mode = mode

    def _emit_benign_packet(self):
        src = random.choice(BENIGN_IPS)
        dst_port = random.choice(COMMON_PORTS)
        flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False,
                  "PSH": random.random() < 0.3, "URG": False}
        return dict(
            src_ip=src, dst_ip=SERVER_IP,
            src_port=random.randint(1024, 65535), dst_port=dst_port,
            protocol="TCP", length=random.randint(60, 1400), flags=flags,
        )

    def _emit_portscan_packet(self):
        attacker = ATTACKER_IPS[0]
        dst_port = random.randint(1, 65535)
        flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False,
                  "PSH": False, "URG": False}
        return dict(
            src_ip=attacker, dst_ip=SERVER_IP,
            src_port=random.randint(1024, 65535), dst_port=dst_port,
            protocol="TCP", length=60, flags=flags,
        )

    def _emit_dos_volumetric_packet(self):
        attacker = random.choice(ATTACKER_IPS)
        flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False,
                  "PSH": False, "URG": False}
        return dict(
            src_ip=attacker, dst_ip=SERVER_IP,
            src_port=random.randint(1024, 65535), dst_port=80,
            protocol="TCP", length=random.randint(40, 200), flags=flags,
        )

    def _emit_dos_slow_packet(self):
        attacker = ATTACKER_IPS[1]
        flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False,
                  "PSH": True, "URG": False}
        return dict(
            src_ip=attacker, dst_ip=SERVER_IP,
            src_port=44444, dst_port=80,
            protocol="TCP", length=20, flags=flags,
        )

    def step(self) -> list[Alert]:
        """Emit one packet according to current mode, return any alerts."""
        if self.mode == "benign":
            pkt = self._emit_benign_packet()
        elif self.mode == "portscan":
            pkt = self._emit_portscan_packet()
        elif self.mode == "dos_volumetric":
            pkt = self._emit_dos_volumetric_packet()
        else:
            pkt = self._emit_dos_slow_packet()

        self._packet_count += 1
        alerts = self.detector.ingest_packet(**pkt, ts=time.time())
        for a in alerts:
            if self.on_alert:
                self.on_alert(a)
        return alerts

    async def run(self, interval_benign=0.05, interval_attack=0.005):
        """Async loop - call from an asyncio task. Emits packets continuously."""
        self.running = True
        last_stat = time.time()
        while self.running:
            interval = interval_benign if self.mode == "benign" else interval_attack
            self.step()

            if time.time() - last_stat >= 1.0:
                if self.on_stat:
                    self.on_stat({
                        "packet_count": self._packet_count,
                        "mode": self.mode,
                        "active_flows": len(self.detector.tracker.active_flows()),
                    })
                last_stat = time.time()

            await asyncio.sleep(interval)

    def stop(self):
        self.running = False
