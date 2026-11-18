setup:
	python -m venv .venv
	.venv/Scripts/python -m pip install -r requirements-dev.txt
run-server:
	python run.py
run-demo-normal:
	python scripts/generate_demo_traffic.py --mode normal
run-demo-abnormal:
	python scripts/generate_demo_traffic.py --mode abnormal --rate 25 --duration 5
run-tests:
	python -m pytest -q
run-ns2-normal:
	ns simulations/ns2_topology.tcl normal
run-ns2-abnormal:
	ns simulations/ns2_topology.tcl abnormal

