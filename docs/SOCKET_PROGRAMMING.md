# Socket programming

TCP messages use a four-byte network-order length prefix followed by JSON; this handles partial reads and multiple messages. UDP uses one JSON datagram, capped at 65,507 bytes, and may lose or reorder messages. `app.monitoring.protocol` provides framing and validation. Test with `frame()`/`extract_frames()` and send only to the local gateway in a controlled lab. Wireshark filters: `tcp`, `udp`, `icmp`, and `host 127.0.0.1`.

