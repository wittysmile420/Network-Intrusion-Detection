# Smart Network Intrusion Detection System (SNIDS)

SNIDS is a safe, header-only network monitoring and rule-based alerting project for the Jaypee Institute of Information Technology Computer Networks Lab. It captures or replays TCP, UDP, and ICMP metadata, stores derived records in SQLite, exposes a Flask dashboard/API, and produces reports. It never stores payloads, attacks hosts, injects packets, blocks traffic, or targets public systems.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
python run.py
```

Open http://127.0.0.1:5000, then run `python scripts\generate_demo_traffic.py --mode normal` or `--mode abnormal`. Run tests with `python -m pytest -q`.

## Architecture

Flask routes -> SQLite header records -> statistics/detection -> dashboard/reports. Optional Scapy capture can be added without changing the safe demo path. NS2 assets and a deterministic fallback trace are in [simulations](simulations).

## Academic details

Institute: Jaypee Institute of Information Technology, Sector-128. Course: Computer Networks Lab. Submitted to: Mr. Prateek Kumar Soni. Batch: F-9. Members: Avi Sharma, Rhythm Jain, Sarthak Suman V., Harshit Chauhan.

See [docs](docs) for installation, architecture, detection rules, simulation, demo, testing, API, and ethics documentation.

For the full Windows/WSL setup, fallback procedures, feature verification, and recovery steps, use [Complete Operation Guide](docs/COMPLETE_OPERATION_GUIDE.md).

