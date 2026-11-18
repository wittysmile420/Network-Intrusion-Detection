# NS2 simulation

Run `ns simulations/ns2_topology.tcl normal` and `ns simulations/ns2_topology.tcl abnormal` in a real NS2 installation. The four-node topology emits trace and NAM files. `+` is a send, `r` a receive, and `d` a drop. Delivery and loss are computed by `app.simulation.ns2_parser`. If NS2 is unavailable, `simulations/sample_normal.tr` and `sample_abnormal.tr` are deterministic fallback evidence and are explicitly not claimed as live NS2 output.

