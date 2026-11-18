import json
import shutil
import subprocess


def replay(path):
    """Replay header fields from a PCAP/PCAPNG using TShark, without payloads."""
    executable = shutil.which("tshark")
    if not executable:
        raise RuntimeError("TShark is not installed; use demo mode or install Wireshark/TShark")
    command = [executable, "-r", path, "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src",
               "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "frame.len", "-E", "json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    for item in json.loads(result.stdout or "[]"):
        fields = item.get("_source", {}).get("layers", {})
        protocol = str(fields.get("_ws.col.Protocol", [""])[0]).upper()
        if protocol in {"TCP", "UDP", "ICMP"}:
            yield {"timestamp": fields.get("frame.time_epoch", [""])[0], "source_ip": fields.get("ip.src", [""])[0],
                   "destination_ip": fields.get("ip.dst", [""])[0], "protocol": protocol,
                   "packet_size": int(fields.get("frame.len", [0])[0]), "capture_source": path}

