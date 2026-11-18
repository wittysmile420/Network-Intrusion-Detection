from app import create_app

app = create_app()
with app.test_client() as client:
    client.post("/api/ingest", json={"capture_source": "seed",
        "packets": [{"protocol": "TCP", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "packet_size": 60},
                    {"protocol": "UDP", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "packet_size": 64},
                    {"protocol": "ICMP", "source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "packet_size": 84, "icmp_type": 8}]})
print("Seeded safe loopback header records.")
