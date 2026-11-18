from app.capture.packet_processor import normalize_packet
from app.detection.engine import DetectionEngine
from app.monitoring.protocol import extract_frames, frame, validate_datagram
from app.simulation.ns2_parser import parse_trace


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


def test_tcp_framing():
    messages, remainder = extract_frames(frame({"kind": "heartbeat"}) + frame({"kind": "alert"}))
    assert len(messages) == 2 and remainder == b""


def test_udp_validation():
    assert validate_datagram(b'{"kind":"stats"}')["kind"] == "stats"


def test_ns2_parser():
    result = parse_trace("simulations/sample_abnormal.tr")
    assert result["packet_sent"] == 2 and result["packet_loss"] == 50.0

