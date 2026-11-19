# Complete SNIDS Operation Guide

This guide is the authoritative procedure for running every implemented feature. Use the safe demo if live capture, NS2, Scapy, or Npcap is unavailable.

## 1. Safety boundary

SNIDS may run only against loopback or explicitly authorized networks:

- Default synthetic target: `127.0.0.1`
- Capture privacy mode: header fields only
- No payload storage
- No packet injection
- No blocking or disruption
- No public-host targeting

Do not change the demo target unless written authorization covers the destination network.

## 2. Requirements

Required:

- Python 3.11 or later
- Flask
- pytest
- pytest-cov
- A modern browser

Optional:

- Scapy for live capture
- Npcap for Windows live capture
- Wireshark/TShark for PCAP/PCAPNG replay
- NS2 for real simulation

SQLite is included with Python.

## 3. Windows PowerShell setup

Open PowerShell in the project root.

Do not run WSL commands such as `source`, `wsl`, or `/mnt/c/...` in this
terminal. PowerShell uses `.\`, `.venv\Scripts\Activate.ps1`, and Windows paths.

```powershell
python --version
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python scripts\project_doctor.py
```

Do not run `python -m venv .venv` again after `.venv` already exists. Recreating an existing
environment is unnecessary and may fail while OneDrive, VS Code extensions, Flask, or another
Python process has a virtual-environment executable open.

If `.venv` already exists, activate and install directly:

```powershell
.venv\Scripts\Activate.ps1
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe scripts\project_doctor.py
```

If OneDrive continues to lock the virtual environment, create it outside OneDrive:

```powershell
python -m venv C:\Users\sarth\.venvs\snids
& C:\Users\sarth\.venvs\snids\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python scripts\project_doctor.py
```

If script activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

The doctor must report core project files and writable directories. Flask, pytest, and pytest-cov should display `OK`.

Optional Scapy capture:

```powershell
python -m pip install -e ".[capture]"
```

Install Npcap only from the authorized download source before live capture on Windows.

## 4. Ubuntu/WSL setup

Open WSL in the project:

Do not run Windows-only commands such as `.\.venv\Scripts\Activate.ps1` in this
terminal. WSL uses `source`, `~/.venvs/snids/bin/activate`, and `/mnt/c/...`.

```bash
cd "/mnt/c/Users/sarth/OneDrive/Documents/VS_coding/CN Lab/Lab proj"
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python scripts/project_doctor.py
```

Do not activate `CN Lab/Lab proj/.venv/Scripts/activate` in WSL. That is a Windows
PowerShell virtual environment and cannot execute as a Linux environment.

If Python reports that `ensurepip` or `python3-venv` is missing:

```bash
sudo apt-get update
sudo apt-get install -y python3.12-venv python3-pip
```

Do not recreate the Windows `.venv` inside WSL. Ubuntu/WSL virtual environments should
be stored outside the Windows-mounted project, such as `~/.venvs/snids`:

```bash
mkdir -p ~/.venvs
python3 -m venv ~/.venvs/snids
source ~/.venvs/snids/bin/activate
cd "/mnt/c/Users/sarth/OneDrive/Documents/VS_coding/CN Lab/Lab proj"
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pytest -q
python scripts/project_doctor.py
```

To reuse the WSL environment in later terminals:

```bash
source ~/.venvs/snids/bin/activate
cd "/mnt/c/Users/sarth/OneDrive/Documents/VS_coding/CN Lab/Lab proj"
```

Install NS2 requirements:

```bash
sudo apt-get update
sudo apt-get install -y ns2 tcl8.6 tk8.6 python-is-python3
```

Verify:

```bash
python --version
ns
tclsh8.6
```

`ns` with no script opens the NS2 shell; exit with `exit`.

Optional WSL capture:

```bash
python -m pip install -e ".[capture]"
sudo apt-get install -y tshark
```

WSL live capture can be unreliable because WSL interface visibility differs from Windows. Windows live capture is preferable.

## 5. Automated verification

Run:

```powershell
python -m pytest -q
python -m pytest -q --cov=app --cov-report=term-missing
python -m compileall -q app scripts run.py
python scripts\project_doctor.py
```

WSL use `/` and the same Python commands:

```bash
python -m pytest -q
python -m compileall -q app scripts run.py
python scripts/project_doctor.py
```

Expected:

- Automated tests: all pass
- Compilation: no errors
- Core files: present
- Doctor: no missing core file

If pytest reports a missing module:

```powershell
python -m pip install -r requirements-dev.txt
```

## 6. Start the Flask server

Windows:

```powershell
python run.py
```

WSL:

```bash
python run.py
```

Open:

```text
http://127.0.0.1:5000
```

Health:

```text
GET http://127.0.0.1:5000/api/health
```

Expected JSON:

```json
{"status":"ok","privacy_mode":"header-only"}
```

Stop the server with `Ctrl+C`.

If port 5000 is busy:

```powershell
$env:SNIDS_PORT="5010"
python run.py
```

Then use port `5010` in all commands.

## 7. Safe normal demo

Run this while the server is active:

```powershell
python scripts\generate_demo_traffic.py --mode normal
```

WSL:

```bash
python scripts/generate_demo_traffic.py --mode normal
```

This sends synthetic header records to the loopback ingestion API.

## 8. Safe abnormal demo

```powershell
python scripts\generate_demo_traffic.py --mode abnormal --rate 25 --duration 5
```

Use lower thresholds temporarily only for teaching:

```powershell
$env:SNIDS_TRAFFIC_SPIKE_THRESHOLD="3"
$env:SNIDS_TRAFFIC_SPIKE_WINDOW="60"
$env:SNIDS_SYN_THRESHOLD="3"
$env:SNIDS_SYN_WINDOW="30"
python run.py
```

In WSL:

```bash
SNIDS_TRAFFIC_SPIKE_THRESHOLD=3 SNIDS_SYN_THRESHOLD=3 python run.py
```

Inspect alerts:

```text
GET /api/alerts
GET /api/alerts/<id>
POST /api/alerts/<id>/acknowledge
POST /api/alerts/<id>/resolve
```

## 9. Dashboard verification

Verify:

- System/health status
- Packet totals
- TCP, UDP, and ICMP totals
- Recent packets
- Open alerts
- Alert acknowledge/resolve actions
- CSV/JSON report actions

Refresh the browser after demo traffic. Flask dashboard updates by manual API refresh rather than WebSocket/SSE because real-time streaming is not implemented in the current dashboard.

## 10. API verification

Windows:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/health
Invoke-RestMethod http://127.0.0.1:5000/api/dashboard
Invoke-RestMethod http://127.0.0.1:5000/api/statistics
Invoke-RestMethod http://127.0.0.1:5000/api/packets
Invoke-RestMethod http://127.0.0.1:5000/api/alerts
Invoke-RestMethod -Method Post http://127.0.0.1:5000/api/reports/generate
```

For invalid input testing:

```powershell
try {
  Invoke-RestMethod -Method Post `
    -Uri http://127.0.0.1:5000/api/ingest `
    -ContentType "application/json" `
    -Body '{"packets":[{"protocol":"BAD"}]}'
} catch {
  Write-Output $_.Exception.Response.StatusCode.value__
}
```

Expected status: `400`.

## 11. TCP monitoring verification

TCP framing is implemented in `app/monitoring/protocol.py`.

```powershell
@'
from app.monitoring.protocol import frame, extract_frames

data = frame({"kind":"stats"}) + frame({"kind":"alert"})
messages, remainder = extract_frames(data)
assert len(messages) == 2
assert remainder == b""
print("TCP framing passed")
'@ | python -
```

For a live local TCP helper test, use only `127.0.0.1`:

```powershell
python -c "from app.monitoring.tcp_client import send; send('127.0.0.1',9000,{'kind':'heartbeat'})"
```

Start a TCP server first from another terminal:

```powershell
python -c "from app.monitoring.tcp_server import serve_once; print(serve_once())"
```

## 12. UDP monitoring verification

```powershell
@'
from app.monitoring.protocol import validate_datagram
message = validate_datagram(b'{"kind":"stats"}')
assert message["kind"] == "stats"
print("UDP validation passed")
'@ | python -
```

UDP server:

```powershell
python -c "from app.monitoring.udp_server import receive_once; print(receive_once())"
```

UDP client:

```powershell
python -c "from app.monitoring.udp_client import send; send('127.0.0.1',9001,{'kind':'stats'})"
```

UDP delivery is not guaranteed. If the receive is lost, rerun the receiver and client.

## 13. Reports

Generate:

```text
POST /api/reports/generate
```

CSV/JSON files are written below `reports/`.

Download by ID:

```text
GET /api/reports/<id>/download
```

Filename downloads and traversal protection are also implemented.

Reports contain header/derived values only. They do not contain application payloads.

## 14. Database verification

Default database:

```text
data/snids.db
```

Acceptance database for an isolated test:

```powershell
$env:SNIDS_DATABASE="data\acceptance.db"
python run.py
```

Tables:

- packets
- flows
- alerts
- statistics
- agents
- simulation_runs
- reports

To recreate a disposable test database, stop the server and delete only `data/acceptance.db` or `data/snids.db`.

## 15. Live capture

Scapy:

```powershell
python -m pip install -e ".[capture]"
python -c "from app.capture.scapy_capture import capture; print(next(capture('Loopback')))"
```

Run Npcap live capture only with authorization and the correct interface.

TShark replay:

```powershell
tshark -r evidence.pcap
```

PCAP replay adapter:

```powershell
python -c "from app.capture.tshark_capture import replay; print(next(replay(r'evidence.pcap')))"
```

If Scapy or TShark is missing or permissions fail, use demo traffic instead.

Never capture shared or public networks unless explicitly authorized.

## 16. NS2 simulation

Normal:

```bash
ns simulations/ns2_topology.tcl normal
```

Abnormal:

```bash
ns simulations/ns2_topology.tcl abnormal
```

Parse:

```bash
python scripts/parse_ns2_results.py
```

Generated:

- simulations/results/normal.tr
- simulations/results/abnormal.tr
- simulations/results/normal.nam
- simulations/results/abnormal.nam

Trace notation:

- `+`: send
- `-`: dequeue
- `r`: receive
- `d`: drop

Normal and abnormal traces must be compared by sent, received, loss, and bytes.

## 17. NS2 fallback

Use fallback traces if NS2 is missing or broken:

- simulations/sample_normal.tr
- simulations/sample_abnormal.tr

Parse:

```powershell
python -c "from app.simulation.ns2_parser import parse_trace; print(parse_trace(r'simulations/sample_normal.tr')); print(parse_trace(r'simulations/sample_abnormal.tr'))"
```

Label fallback values as deterministic sample evidence, not real NS2 output.

## 18. Installation failure recovery

### `pip` package discovery error

Ensure [pyproject.toml](../pyproject.toml) contains:

```toml
[tool.setuptools.packages.find]
include = ["app*"]
```

Then:

```powershell
python -m pip install -e ".[capture]"
```

### `flask` missing

```powershell
python -m pip install -r requirements-dev.txt
```

### `python` missing in WSL

```bash
sudo apt-get install -y python-is-python3
python --version
```

### `/bin/tclsh8.6` missing

```bash
sudo apt-get install -y tcl8.6 tk8.6
ls -l /bin/tclsh8.6
```

If NS2 still warns, reinstall/rebuild NS2 with matching Tcl 8.6 libraries.

### Backslash used in WSL

Use forward slashes:

```bash
ns simulations/ns2_topology.tcl normal
```

Do not use:

```bash
ns simulations\ns2_topology.tcl normal
```

### Missing `simulations/results`

The Tcl script creates it automatically. Otherwise:

```bash
mkdir -p simulations/results
```

## 19. Runtime failure recovery

### Port already in use

```powershell
$env:SNIDS_PORT="5010"
python run.py
```

### Dashboard template error

The blueprint must expose `template_folder="templates"` and `static_folder="static"`. Then restart Flask.

### Database locked

- Stop all Flask processes
- Do not run multiple writers against the same database
- Use an isolated `acceptance.db`

### No packets appear

- Verify server health
- Verify safe demo target
- Run normal demo
- Check `/api/dashboard`
- Check `/api/packets`

### No alert appears

- The default thresholds may be too high
- Use abnormal demo mode
- Lower thresholds temporarily
- Verify packets were stored
- Review rule documentation

### Capture failure

- Use demo/replay mode
- Install Npcap or TShark
- Check interface permissions
- Never use capture outside authorized networks

### NS2 failure

- Verify `ns`
- Verify `tclsh8.6`
- Create `simulations/results`
- Use sample fallback traces
- Reinstall/rebuild NS2 if libraries are mismatched

## 20. 10–15 minute demonstration

1. Run the doctor and tests.
2. Start Flask.
3. Open dashboard and health endpoint.
4. Run normal safe traffic.
5. Explain TCP/UDP/ICMP fields.
6. Run abnormal traffic.
7. Show alert lifecycle.
8. Generate and download reports.
9. Run NS2 normal and abnormal scenarios.
10. Parse and compare metrics.
11. Explain limitations and fallback evidence.
12. Stop server and demo processes.

## 21. End-of-session cleanup

Stop Flask with `Ctrl+C`.

For a clean disposable test database:

```powershell
Remove-Item data\acceptance.db -ErrorAction SilentlyContinue
Remove-Item reports\acceptance -Recurse -Force -ErrorAction SilentlyContinue
```

Do not delete `data/snids.db` unless all stored demo evidence is no longer needed.

Do not delete `simulations/results` while preserving NS2 evidence.
