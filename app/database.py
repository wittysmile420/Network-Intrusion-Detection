import sqlite3
from contextlib import contextmanager


SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
 id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
 destination_ip TEXT NOT NULL, source_port INTEGER, destination_port INTEGER,
 protocol TEXT NOT NULL, packet_size INTEGER NOT NULL, tcp_flags TEXT,
 icmp_type INTEGER, icmp_code INTEGER, capture_source TEXT NOT NULL,
 interface TEXT, direction TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(source_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(destination_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE TABLE IF NOT EXISTS flows (
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT, destination_ip TEXT,
 protocol TEXT, source_port INTEGER, destination_port INTEGER,
 packet_count INTEGER, byte_count INTEGER, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
 rule_name TEXT NOT NULL, source_ip TEXT, destination_ip TEXT, protocol TEXT,
 description TEXT NOT NULL, observed_value TEXT, threshold_value TEXT,
 time_window INTEGER, packet_count INTEGER, status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE TABLE IF NOT EXISTS statistics (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, total_packets INTEGER,
 total_bytes INTEGER, tcp_count INTEGER, udp_count INTEGER, icmp_count INTEGER,
 packets_per_minute REAL, bytes_per_minute REAL
);
CREATE TABLE IF NOT EXISTS agents (
 agent_id TEXT PRIMARY KEY, last_seen TEXT NOT NULL, address TEXT, metadata TEXT
);
CREATE TABLE IF NOT EXISTS simulation_runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, scenario TEXT, source TEXT,
 packet_sent INTEGER, packet_received INTEGER, packet_loss REAL,
 average_delay REAL, created_at TEXT
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, path TEXT, created_at TEXT
);
"""


def init_db(path):
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

