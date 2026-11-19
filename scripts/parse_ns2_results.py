import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.simulation.ns2_parser import parse_trace


for scenario in ("normal", "abnormal"):
    print(f"{scenario}: {parse_trace(f'simulations/results/{scenario}.tr')}")
