import importlib.util
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(label, available, detail):
    print(f"[{'OK' if available else 'INFO'}] {label}: {detail}")


def main():
    print(f"SNIDS project doctor")
    print(f"Root: {ROOT}")
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")

    check("Repository root", (ROOT / "app").is_dir(), "app/ directory found")
    check("Flask", importlib.util.find_spec("flask") is not None, "required for the dashboard")
    check("pytest", importlib.util.find_spec("pytest") is not None, "required for automated tests")
    check("pytest-cov", importlib.util.find_spec("pytest_cov") is not None, "coverage testing")
    check("Scapy", importlib.util.find_spec("scapy") is not None, "optional live capture")
    check("TShark", shutil.which("tshark") is not None, shutil.which("tshark") or "optional replay adapter")
    check("NS2", shutil.which("ns") is not None, shutil.which("ns") or "fallback traces remain usable")
    check("Tcl 8.6", shutil.which("tclsh8.6") is not None, shutil.which("tclsh8.6") or "check NS2 installation")

    required = [
        "app/__init__.py", "app/web/routes.py", "app/web/templates/dashboard.html",
        "app/database.py", "app/detection/engine.py", "app/reporting/report_service.py",
        "simulations/ns2_topology.tcl", "simulations/sample_normal.tr",
        "simulations/sample_abnormal.tr", "scripts/generate_demo_traffic.py",
    ]
    missing = [item for item in required if not (ROOT / item).is_file()]
    check("Core project files", not missing, "all present" if not missing else "missing: " + ", ".join(missing))

    (ROOT / "data").mkdir(parents=True, exist_ok=True)
    (ROOT / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "simulations" / "results").mkdir(parents=True, exist_ok=True)
    check("Writable directories", True, "data/, reports/, simulations/results/ ready")


if __name__ == "__main__":
    main()
