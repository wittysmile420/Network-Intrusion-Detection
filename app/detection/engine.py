from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress


def _time(packet):
    value = packet["timestamp"].replace("Z", "+00:00")
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc) if "+" not in value else datetime.fromisoformat(value)


class DetectionEngine:
    def __init__(self, thresholds=None, trusted_networks=None):
        self.thresholds = thresholds or {
            "traffic_spike": (100, 60), "repeated_syn": (20, 30),
            "abnormal_icmp": (50, 30), "udp_spike": (100, 30),
        }
        self.trusted_networks = [ipaddress.ip_network(x) for x in (trusted_networks or ["127.0.0.0/8"])]

    def detect(self, packets):
        packets = list(packets)
        alerts = []
        grouped = defaultdict(list)
        for packet in packets:
            grouped[packet["source_ip"]].append(packet)
        for source, items in grouped.items():
            alerts.extend(self._threshold_alerts(source, items))
        alerts.extend(self._unexpected_hosts(packets))
        alerts.extend(self._repeating_flows(packets))
        return alerts

    def _threshold_alerts(self, source, items):
        alerts = []
        for rule, protocol, label in [
            ("traffic_spike", None, "Traffic spike"),
            ("abnormal_icmp", "ICMP", "Abnormal ICMP"),
            ("udp_spike", "UDP", "UDP spike"),
        ]:
            threshold, window = self.thresholds[rule]
            selected = [p for p in items if protocol is None or p["protocol"] == protocol]
            evidence = self._window_evidence(selected, threshold, window)
            if evidence:
                alerts.append(self._alert(rule, label, evidence, threshold, window, source))
        threshold, window = self.thresholds["repeated_syn"]
        syns = [p for p in items if p["protocol"] == "TCP" and "S" in (p.get("tcp_flags") or "") and "A" not in (p.get("tcp_flags") or "")]
        by_destination = Counter(p["destination_ip"] for p in syns)
        for destination, count in by_destination.items():
            selected = [p for p in syns if p["destination_ip"] == destination]
            evidence = self._window_evidence(selected, threshold, window)
            if evidence:
                alerts.append(self._alert("repeated_syn", "Repeated SYN attempts", evidence, threshold, window, source))
        return alerts

    def _unexpected_hosts(self, packets):
        alerts = []
        for p in packets:
            try:
                approved = any(ipaddress.ip_address(p["destination_ip"]) in net for net in self.trusted_networks)
            except ValueError:
                approved = False
            if not approved:
                alerts.append(self._alert("unexpected_host", "Unexpected host", [p], 0, 0, p["source_ip"]))
        return alerts

    def _repeating_flows(self, packets):
        groups = defaultdict(list)
        for p in packets:
            groups[(p["source_ip"], p["destination_ip"], p["protocol"], p.get("destination_port"))].append(p)
        alerts = []
        for key, items in groups.items():
            evidence = self._window_evidence(items, 5, 60)
            if evidence:
                alerts.append(self._alert("repeating_flow", "Repeating communication flow", evidence, 5, 60, key[0]))
        return alerts

    @staticmethod
    def _window_evidence(items, threshold, window):
        ordered = sorted(items, key=_time)
        for end, packet in enumerate(ordered):
            start = _time(packet)
            evidence = [candidate for candidate in ordered[:end + 1]
                        if (start - _time(candidate)).total_seconds() <= window]
            if len(evidence) >= threshold:
                return evidence
        return []

    @staticmethod
    def _alert(rule, label, items, threshold, window, source):
        sample = items[-1]
        observed = len(items)
        detail = f"{label}: {observed} {sample['protocol']} packets from {source}"
        if rule == "abnormal_icmp":
            detail += f" (ICMP type {sample.get('icmp_type', 'unknown')})"
        return {
            "timestamp": sample["timestamp"], "severity": "high" if rule in {"repeated_syn", "unexpected_host"} else "medium",
            "rule_name": rule, "source_ip": source, "destination_ip": sample["destination_ip"],
            "protocol": sample["protocol"], "description": detail, "observed_value": str(observed),
            "threshold_value": str(threshold), "time_window": window, "packet_count": observed, "status": "open",
        }
