# NS2 simulation

## Linux/WSL commands

Use forward slashes when running in Linux or WSL:

```bash
cd "/mnt/c/Users/sarth/OneDrive/Documents/VS_coding/CN Lab/Lab proj"
ns simulations/ns2_topology.tcl normal
ns simulations/ns2_topology.tcl abnormal
python scripts/parse_ns2_results.py
```

The TCL script creates `simulations/results/` automatically. It emits `normal.tr`, `abnormal.tr`, `normal.nam`, and `abnormal.nam`.

On Ubuntu/WSL, install the required executables if they are missing:

```bash
sudo apt-get update
sudo apt-get install -y tcl8.6 tk8.6 python-is-python3
```

Verify:

```bash
python --version
tclsh8.6
```

Exit the Tcl shell by typing `exit` or pressing Ctrl+D.

## NS2 Tcl/Tk warning

If NS2 reports that `/bin/tclsh8.6` is missing or falls back to another Tcl shell, `/bin/tclsh8.6` is absent or the NS2 binary was built with a mismatched Tcl/Tk version. Check:

```bash
which ns
which tclsh
tclsh8.6 <<'EOF'
puts "Tcl is available"
EOF
```

Some Linux distributions no longer install an executable named `tclsh8.6`. Install Tcl 8.6 and the NS2/Tcl development packages using your distribution package manager, or reinstall/rebuild NS2. The warning is a platform compatibility warning; a script that cannot start due to this mismatch must not be presented as successful NS2 evidence.

The four-node topology emits trace and NAM files. `+` is a send, `r` a receive, and `d` a drop. Delivery and loss are computed by `app.simulation.ns2_parser`.

If NS2 is unavailable or its Tcl/Tk build is broken, `simulations/sample_normal.tr` and `simulations/sample_abnormal.tr` are deterministic fallback evidence. They are explicitly not claimed to be live NS2 output.

