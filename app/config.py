import os
from pathlib import Path


def _csv(name, default):
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


class Config:
    HOST = os.getenv("SNIDS_HOST", "127.0.0.1")
    PORT = int(os.getenv("SNIDS_PORT", "5000"))
    DEBUG = os.getenv("SNIDS_DEBUG", "false").lower() == "true"
    DATABASE = os.getenv("SNIDS_DATABASE", "data/snids.db")
    CAPTURE_SOURCE = os.getenv("SNIDS_CAPTURE_SOURCE", "demo")
    CAPTURE_INTERFACE = os.getenv("SNIDS_CAPTURE_INTERFACE", "")
    TRUSTED_NETWORKS = _csv(
        "SNIDS_TRUSTED_NETWORKS",
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    )
    THRESHOLDS = {
        "traffic_spike": (int(os.getenv("SNIDS_TRAFFIC_SPIKE_THRESHOLD", "100")),
                          int(os.getenv("SNIDS_TRAFFIC_SPIKE_WINDOW", "60"))),
        "repeated_syn": (int(os.getenv("SNIDS_SYN_THRESHOLD", "20")),
                         int(os.getenv("SNIDS_SYN_WINDOW", "30"))),
        "abnormal_icmp": (int(os.getenv("SNIDS_ICMP_THRESHOLD", "50")),
                          int(os.getenv("SNIDS_ICMP_WINDOW", "30"))),
        "udp_spike": (int(os.getenv("SNIDS_UDP_THRESHOLD", "100")),
                      int(os.getenv("SNIDS_UDP_WINDOW", "30"))),
    }
    TCP_MONITOR_HOST = os.getenv("SNIDS_TCP_MONITOR_HOST", "127.0.0.1")
    TCP_MONITOR_PORT = int(os.getenv("SNIDS_TCP_MONITOR_PORT", "9000"))
    UDP_MONITOR_HOST = os.getenv("SNIDS_UDP_MONITOR_HOST", "127.0.0.1")
    UDP_MONITOR_PORT = int(os.getenv("SNIDS_UDP_MONITOR_PORT", "9001"))
    REPORT_DIR = os.getenv("SNIDS_REPORT_DIR", "reports")
    LOG_LEVEL = os.getenv("SNIDS_LOG_LEVEL", "INFO")
    PRIVACY_MODE = os.getenv("SNIDS_PRIVACY_MODE", "header-only")

