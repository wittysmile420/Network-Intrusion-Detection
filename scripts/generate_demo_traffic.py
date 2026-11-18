import argparse, json, time, urllib.request
from datetime import datetime, timezone


def packet(protocol, i, abnormal=False):
    flags = "S" if protocol == "TCP" else None
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1", "source_port": 40000 + i, "destination_port": 8080,
            "protocol": protocol, "packet_size": 60 if protocol == "TCP" else 64,
            "tcp_flags": flags, "icmp_type": 8 if protocol == "ICMP" else None}


def main():
    parser = argparse.ArgumentParser(description="Generate safe loopback SNIDS demo traffic; never targets external hosts.")
    parser.add_argument("--mode", choices=["normal", "abnormal"], default="normal")
    parser.add_argument("--rate", type=float, default=5)
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/ingest")
    args = parser.parse_args()
    count = min(max(int(args.rate * args.duration), 1), 500)
    protocols = ["TCP", "UDP", "ICMP"] if args.mode == "normal" else ["TCP"] * count
    packets = [packet(protocols[i % len(protocols)], i, args.mode == "abnormal") for i in range(count)]
    print(f"Generating {count} header-only packets to loopback (mode={args.mode}, dry_run={args.dry_run}).")
    if not args.dry_run:
        data = json.dumps({"capture_source": "safe-demo", "packets": packets}).encode()
        request = urllib.request.Request(args.url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            print(response.read().decode())
    time.sleep(min(args.duration, 30))


if __name__ == "__main__":
    main()

