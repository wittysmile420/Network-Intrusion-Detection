import socket
from .protocol import validate_datagram


def receive_once(host="127.0.0.1", port=9001, timeout=5):
    """Receive one bounded UDP JSON datagram for a local classroom gateway."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        server.settimeout(timeout)
        data, address = server.recvfrom(65507)
    return address, validate_datagram(data)

