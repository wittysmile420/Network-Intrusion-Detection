from app import create_app


def test_api_ingest_and_lifecycle(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db"), "REPORT_DIR": str(tmp_path / "reports"),
                      "THRESHOLDS": {"traffic_spike": (2, 60), "repeated_syn": (20, 30), "abnormal_icmp": (50, 30),
                                     "udp_spike": (100, 30)}})
    client = app.test_client()
    response = client.post("/api/ingest", json={"packets": [
        {"protocol": "TCP", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "packet_size": 60},
        {"protocol": "TCP", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "packet_size": 60}]})
    assert response.status_code == 201
    assert client.post("/api/ingest", json={"packets": [{"protocol": "BAD"}]}).status_code == 400
    assert client.get("/api/health").json["status"] == "ok"
    assert client.post("/api/reports/generate").status_code == 201
