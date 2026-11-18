# Architecture

The application separates capture, normalization, analysis, detection, monitoring, reporting, simulation, and web presentation. SQLite stores only header-derived data.

```mermaid
flowchart LR
  C[Safe demo / PCAP / optional live capture] --> N[Normalizer]
  N --> D[(SQLite)]
  D --> E[Detection engine]
  E --> A[Alerts]
  D --> W[Flask API + dashboard]
  S[NS2 or sample trace] --> M[Metrics]
```

All API input is validated, reports are path-confined, and payloads are intentionally discarded.

