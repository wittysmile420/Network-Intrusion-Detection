from collections import Counter
from datetime import datetime, timedelta, timezone


def summarize(packets):
    packets = list(packets)
    protocols = Counter(p["protocol"] for p in packets)
    sources = Counter(p["source_ip"] for p in packets)
    destinations = Counter(p["destination_ip"] for p in packets)
    total_bytes = sum(p["packet_size"] for p in packets)
    timeline = Counter()
    flows = Counter()
    for p in packets:
        try:
            minute = datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00")).replace(second=0, microsecond=0)
            minute_key = minute.isoformat()
        except (KeyError, TypeError, ValueError):
            minute_key = "unknown"
        timeline[minute_key] += 1
        flows[(p["source_ip"], p["destination_ip"], p["protocol"], p.get("destination_port"))] += 1
    return {
        "total_packets": len(packets), "total_bytes": total_bytes,
        "tcp": protocols["TCP"], "udp": protocols["UDP"], "icmp": protocols["ICMP"],
        "tcp_percentage": round(protocols["TCP"] * 100 / len(packets), 2) if packets else 0,
        "udp_percentage": round(protocols["UDP"] * 100 / len(packets), 2) if packets else 0,
        "icmp_percentage": round(protocols["ICMP"] * 100 / len(packets), 2) if packets else 0,
        "packets_per_minute": len(packets), "bytes_per_minute": total_bytes,
        "unique_sources": len(sources), "unique_destinations": len(destinations),
        "top_sources": sources.most_common(5), "top_destinations": destinations.most_common(5),
        "traffic_timeline": sorted(timeline.items()),
        "top_flows": [
            {"source_ip": key[0], "destination_ip": key[1], "protocol": key[2],
             "destination_port": key[3], "packet_count": count}
            for key, count in flows.most_common(10)
        ],
    }

