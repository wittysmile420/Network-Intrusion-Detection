import socket
from .protocol import MAX_UDP_MESSAGE


def send(host, port, message):
    import json
    data = json.dumps(message, separators=(",", ":")).encode()
    if len(data) > MAX_UDP_MESSAGE:
        raise ValueError("UDP datagram exceeds safe maximum")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.sendto(data, (host, port))

