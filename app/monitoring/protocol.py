import json
import struct

MAX_UDP_MESSAGE = 65507


def frame(message):
    payload = json.dumps(message, separators=(",", ":")).encode()
    return struct.pack("!I", len(payload)) + payload


def extract_frames(buffer):
    messages = []
    while len(buffer) >= 4:
        size = struct.unpack("!I", buffer[:4])[0]
        if size > 1_000_000:
            raise ValueError("TCP frame exceeds 1 MB")
        if len(buffer) < size + 4:
            break
        messages.append(json.loads(buffer[4:size + 4]))
        buffer = buffer[size + 4:]
    return messages, buffer


def validate_datagram(data):
    if len(data) > MAX_UDP_MESSAGE:
        raise ValueError("UDP datagram exceeds safe maximum")
    message = json.loads(data.decode())
    if not isinstance(message, dict):
        raise ValueError("UDP message must be a JSON object")
    return message

