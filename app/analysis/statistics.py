from collections import Counter


def summarize(packets):
    packets = list(packets)
    protocols = Counter(p["protocol"] for p in packets)
    sources = Counter(p["source_ip"] for p in packets)
    destinations = Counter(p["destination_ip"] for p in packets)
    total_bytes = sum(p["packet_size"] for p in packets)
    return {
        "total_packets": len(packets), "total_bytes": total_bytes,
        "tcp": protocols["TCP"], "udp": protocols["UDP"], "icmp": protocols["ICMP"],
        "tcp_percentage": round(protocols["TCP"] * 100 / len(packets), 2) if packets else 0,
        "udp_percentage": round(protocols["UDP"] * 100 / len(packets), 2) if packets else 0,
        "icmp_percentage": round(protocols["ICMP"] * 100 / len(packets), 2) if packets else 0,
        "packets_per_minute": len(packets), "bytes_per_minute": total_bytes,
        "unique_sources": len(sources), "unique_destinations": len(destinations),
        "top_sources": sources.most_common(5), "top_destinations": destinations.most_common(5),
    }

