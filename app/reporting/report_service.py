import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_reports(packets, alerts, directory):
    Path(directory).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = Path(directory) / f"traffic_{stamp}.csv"
    json_path = Path(directory) / f"snids_{stamp}.json"
    fields = ["id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
              "protocol", "packet_size", "tcp_flags", "icmp_type", "icmp_code", "capture_source", "interface", "direction"]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(packets)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump({"privacy": "header-only", "packets": packets, "alerts": alerts}, handle, indent=2)
    text_path = Path(directory) / f"summary_{stamp}.txt"
    tcp = sum(p["protocol"] == "TCP" for p in packets)
    udp = sum(p["protocol"] == "UDP" for p in packets)
    icmp = sum(p["protocol"] == "ICMP" for p in packets)
    text_path.write_text(
        "SNIDS Academic Traffic Summary\n"
        f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
        "Privacy: header-level records only; payloads are not collected.\n\n"
        f"Packets: {len(packets)}\nTCP: {tcp}\nUDP: {udp}\nICMP: {icmp}\n"
        f"Open alerts: {sum(a.get('status') == 'open' for a in alerts)}\n"
        f"Total alerts: {len(alerts)}\n\n"
        "Limitations: Statistics depend on authorized demo/live capture coverage. "
        "UDP delivery and rule thresholds may produce false positives or false negatives.\n",
        encoding="utf-8",
    )
    return {"csv": str(csv_path), "json": str(json_path), "text": str(text_path)}

