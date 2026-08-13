"""
Live Packet Sniffer (Scapy)
------------------------------
Wraps scapy.sniff to feed packets into the HybridDetector in real time.
Requires root/admin privileges and a valid interface name (e.g. eth0, wlan0).

Usage:
    from app.detection.hybrid import HybridDetector
    from app.features.sniffer import start_live_capture

    detector = HybridDetector()
    start_live_capture(detector, iface="eth0", on_alert=lambda a: print(a))

NOTE: On most systems this needs to run as root:
    sudo -E $(which python) -m app.features.sniffer
"""

from scapy.all import sniff, IP, TCP, UDP
from app.detection.hybrid import HybridDetector


def _extract_flags(pkt) -> dict:
    if TCP in pkt:
        f = pkt[TCP].flags
        return {
            "SYN": bool(f & 0x02),
            "ACK": bool(f & 0x10),
            "FIN": bool(f & 0x01),
            "RST": bool(f & 0x04),
            "PSH": bool(f & 0x08),
            "URG": bool(f & 0x20),
        }
    return {}


def packet_to_kwargs(pkt) -> dict | None:
    if IP not in pkt:
        return None

    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    src_port = dst_port = 0
    if TCP in pkt:
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    return dict(
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        length=len(pkt),
        flags=_extract_flags(pkt),
    )


def start_live_capture(detector: HybridDetector, iface: str = None,
                        on_alert=None, count: int = 0):
    """
    Blocking call. Sniffs packets and feeds them into the detector.
    on_alert(alert) is called for every new alert.
    count=0 means sniff indefinitely.
    """

    def _handle(pkt):
        kwargs = packet_to_kwargs(pkt)
        if kwargs is None:
            return
        alerts = detector.ingest_packet(**kwargs)
        for a in alerts:
            if on_alert:
                on_alert(a)

    sniff(iface=iface, prn=_handle, store=False, count=count)


if __name__ == "__main__":
    det = HybridDetector()
    print("[+] Starting live capture... (Ctrl+C to stop)")
    start_live_capture(det, on_alert=lambda a: print(f"[ALERT] {a.severity} {a.attack_type} "
                                                       f"from {a.src_ip} -> {a.dst_ip}:{a.dst_port} "
                                                       f"({a.reason})"))
