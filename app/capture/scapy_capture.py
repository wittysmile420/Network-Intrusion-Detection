def capture(interface, packet_filter="tcp or udp or icmp", count=0):
    """Yield header-only records from an authorized interface using Scapy.

    Scapy is optional; ImportError and permission errors are intentionally
    surfaced so callers can switch to replay/demo mode.
    """
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed; use PCAP replay or demo mode") from exc
    from .packet_processor import normalize_packet

    def convert(packet):
        if packet.haslayer("TCP"):
            layer, protocol = packet["TCP"], "TCP"
            values = {"source_port": layer.sport, "destination_port": layer.dport, "tcp_flags": str(layer.flags)}
        elif packet.haslayer("UDP"):
            layer, protocol = packet["UDP"], "UDP"
            values = {"source_port": layer.sport, "destination_port": layer.dport}
        elif packet.haslayer("ICMP"):
            layer, protocol = packet["ICMP"], "ICMP"
            values = {"icmp_type": layer.type, "icmp_code": layer.code}
        else:
            return None
        values.update({"protocol": protocol, "source_ip": packet["IP"].src, "destination_ip": packet["IP"].dst,
                       "packet_size": len(packet)})
        return normalize_packet(values, "scapy", interface)

    for packet in sniff(iface=interface, filter=packet_filter, count=count, store=False):
        record = convert(packet)
        if record:
            yield record

