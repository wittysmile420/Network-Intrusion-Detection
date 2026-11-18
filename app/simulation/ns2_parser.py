import re
from pathlib import Path


TRACE = re.compile(r"(?P<event>[+\-rd])\s+(?P<time>\S+)\s+(?P<src>\d+)\s+(?P<dst>\d+)\s+(?P<type>\S+)\s+(?P<size>\d+)")


def parse_trace(path):
    sent = received = dropped = 0
    first = last = None
    total_bytes = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = TRACE.match(line.strip())
        if not match:
            continue
        event, time, size = match.group("event"), float(match.group("time")), int(match.group("size"))
        first = time if first is None else min(first, time)
        last = time if last is None else max(last, time)
        total_bytes += size
        if event == "+":
            sent += 1
        elif event == "r":
            received += 1
        elif event == "d":
            dropped += 1
    return {"packet_sent": sent, "packet_received": received, "packet_loss": round((sent - received) * 100 / sent, 2) if sent else 0,
            "duration": round((last or 0) - (first or 0), 6), "bytes_observed": total_bytes}
