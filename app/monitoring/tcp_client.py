import socket
from .protocol import frame


def send(host, port, message, timeout=5):
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.sendall(frame(message))

