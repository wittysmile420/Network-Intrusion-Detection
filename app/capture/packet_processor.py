from datetime import datetime, timezone
from uuid import uuid4


def normalize_packet(packet, capture_source="demo", interface=None):
    """Normalize a mapping or Scapy-like packet without retaining payloads."""
    get = packet.get if isinstance(packet, dict) else lambda key, default=None: getattr(packet, key, default)
    protocol = str(get("protocol", "")).upper()
    if protocol not in {"TCP", "UDP", "ICMP"}:
        raise ValueError("protocol must be TCP, UDP, or ICMP")
    return {
        "id": str(get("id", uuid4())),
        "timestamp": str(get("timestamp", datetime.now(timezone.utc).isoformat())),
        "source_ip": str(get("source_ip", "127.0.0.1")),
        "destination_ip": str(get("destination_ip", "127.0.0.1")),
        "source_port": get("source_port"),
        "destination_port": get("destination_port"),
        "protocol": protocol,
        "packet_size": int(get("packet_size", 0)),
        "tcp_flags": get("tcp_flags"),
        "icmp_type": get("icmp_type"),
        "icmp_code": get("icmp_code"),
        "capture_source": capture_source,
        "interface": interface,
        "direction": get("direction"),
    }

