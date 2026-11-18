# Detection rules

Traffic spike counts packets per source (100/60s default). Repeated SYN counts TCP packets containing SYN without ACK to a destination (20/30s). Abnormal ICMP counts ICMP packets per source (50/30s). UDP spike counts UDP packets per source (100/30s). Unexpected host checks the destination against `SNIDS_TRUSTED_NETWORKS`. Repeating flow reports five identical source/destination/protocol/port records. Thresholds are environment-configurable. These are transparent heuristics and can produce false positives on busy lab networks.

