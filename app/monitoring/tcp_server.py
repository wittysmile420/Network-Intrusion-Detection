import socket
from .protocol import extract_frames


def serve_once(host="127.0.0.1", port=9000, timeout=5):
    """Receive one framed TCP batch for a local classroom gateway."""
    with socket.create_server((host, port), reuse_port=False) as server:
        server.settimeout(timeout)
        connection, address = server.accept()
        with connection:
            connection.settimeout(timeout)
            data = connection.recv(1_100_000)
        messages, _ = extract_frames(data)
        return address, messages

