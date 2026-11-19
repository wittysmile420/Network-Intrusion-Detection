from app.capture.packet_processor import normalize_packet
from app.detection.engine import DetectionEngine
from app.monitoring.protocol import extract_frames, frame, validate_datagram
from app.simulation.ns2_parser import parse_trace
from datetime import datetime, timedelta, timezone


def p(protocol="TCP", i=0, flags="S"):
    return normalize_packet({"protocol": protocol, "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1",
                             "packet_size": 60, "tcp_flags": flags, "source_port": i, "destination_port": 80})


def test_normalization_and_protocols():
    assert normalize_packet({"protocol": "udp"})["protocol"] == "UDP"
    assert normalize_packet({"protocol": "icmp", "icmp_type": 8})["icmp_type"] == 8


def test_detection_rules():
    packets = [p(i=i) for i in range(5)]
    alerts = DetectionEngine({"traffic_spike": (3, 60), "repeated_syn": (3, 30),
                              "abnormal_icmp": (50, 30), "udp_spike": (100, 30)}).detect(packets)
    assert {a["rule_name"] for a in alerts} >= {"traffic_spike", "repeated_syn", "repeating_flow"}


def test_all_rule_families_and_unexpected_host():
    packets = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    packets += [normalize_packet({"timestamp": (base + timedelta(seconds=i * 0.5)).isoformat(),
                                  "protocol": "ICMP", "source_ip": "127.0.0.1",
                                  "destination_ip": "127.0.0.1", "packet_size": 84,
                                  "icmp_type": 8}) for i in range(50)]
    packets += [normalize_packet({"timestamp": f"2026-01-01T00:00:{i:02d}+00:00",
                                  "protocol": "UDP", "source_ip": "127.0.0.1",
                                  "destination_ip": "127.0.0.1", "packet_size": 64,
                                  "destination_port": 53}) for i in range(30)]
    packets += [normalize_packet({"protocol": "UDP", "source_ip": "127.0.0.1",
                                  "destination_ip": "8.8.8.8", "packet_size": 64})]
    engine = DetectionEngine({"traffic_spike": (100, 60), "repeated_syn": (20, 30),
                              "abnormal_icmp": (50, 30), "udp_spike": (100, 30)},
                             ["127.0.0.0/8"])
    names = {a["rule_name"] for a in engine.detect(packets)}
    assert "abnormal_icmp" in names
    assert "unexpected_host" in names


def test_tcp_framing():
    messages, remainder = extract_frames(frame({"kind": "heartbeat"}) + frame({"kind": "alert"}))
    assert len(messages) == 2 and remainder == b""


def test_udp_validation():
    assert validate_datagram(b'{"kind":"stats"}')["kind"] == "stats"


def test_ns2_parser():
    result = parse_trace("simulations/sample_abnormal.tr")
    assert result["packet_sent"] == 2 and result["packet_loss"] == 50.0

