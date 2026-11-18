from .statistics import summarize


def classify(packet):
    protocol = packet.get("protocol", "").upper()
    if protocol not in {"TCP", "UDP", "ICMP"}:
        raise ValueError("unsupported protocol")
    return protocol


def analyze(packets):
    return summarize(packets)

