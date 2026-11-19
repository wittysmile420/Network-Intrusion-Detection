import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, current_app, jsonify, render_template, request, send_file, Response, stream_with_context

from ..analysis.statistics import summarize
from ..capture.packet_processor import normalize_packet
from ..database import connect
from ..detection.engine import DetectionEngine
from ..reporting.report_service import generate_reports
from ..simulation.ns2_parser import parse_trace

api = Blueprint("api", __name__, template_folder="templates", static_folder="static")


def _rows(conn, query, args=()):
    return [dict(row) for row in conn.execute(query, args).fetchall()]


@api.get("/")
def dashboard():
    return render_template("dashboard.html")


@api.get("/api/health")
def health():
    return jsonify({"status": "ok", "privacy_mode": current_app.config["PRIVACY_MODE"],
                    "capture_status": "demo" if current_app.config["CAPTURE_SOURCE"] in {"demo", "safe-demo"} else "configured",
                    "capture_source": current_app.config["CAPTURE_SOURCE"]})


@api.get("/api/openapi.json")
def openapi():
    return jsonify({
        "openapi": "3.0.3",
        "info": {"title": "SNIDS API", "version": "1.0.0"},
        "servers": [{"url": "/"}],
        "paths": {
            "/api/health": {"get": {"responses": {"200": {"description": "Service health"}}}},
            "/api/dashboard": {"get": {"responses": {"200": {"description": "Dashboard data"}}}},
            "/api/statistics": {"get": {"responses": {"200": {"description": "Traffic statistics"}}}},
            "/api/packets": {"get": {"responses": {"200": {"description": "Packet records"}}}},
            "/api/alerts": {"get": {"responses": {"200": {"description": "Alert records"}}}},
            "/api/ingest": {"post": {"responses": {"201": {"description": "Packets ingested"}, "400": {"description": "Invalid packet data"}}}},
            "/api/reports/generate": {"post": {"responses": {"201": {"description": "Reports generated"}}}},
            "/api/simulation/evidence": {"get": {"responses": {"200": {"description": "NS2 evidence and metrics"}}}},
        },
    })


@api.get("/api/dashboard")
def dashboard_data():
    with connect(current_app.config["DATABASE"]) as conn:
        packets = _rows(conn, "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 500")
        alerts = _rows(conn, "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
        agents = _rows(conn, "SELECT * FROM agents ORDER BY last_seen DESC")
        severities = _rows(conn, "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")
        alert_timeline = _rows(conn, "SELECT substr(timestamp,1,16) AS minute, COUNT(*) AS count FROM alerts GROUP BY minute ORDER BY minute")
    open_alerts = sum(a["status"] == "open" for a in alerts)
    severity_counts = {row["severity"]: row["count"] for row in severities}
    return jsonify({"statistics": summarize(packets), "packets": packets[:20], "alerts": alerts,
                    "alert_severity": severity_counts, "alert_timeline": [[row["minute"], row["count"]] for row in alert_timeline],
                    "open_alerts": open_alerts,
                    "agents": agents, "capture": {"source": current_app.config["CAPTURE_SOURCE"],
                    "interface": current_app.config["CAPTURE_INTERFACE"], "privacy": current_app.config["PRIVACY_MODE"],
                    "status": "demo" if current_app.config["CAPTURE_SOURCE"] in {"demo", "safe-demo"} else "configured"}})


@api.get("/api/statistics")
def statistics():
    with connect(current_app.config["DATABASE"]) as conn:
        packets = _rows(conn, "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 5000")
    return jsonify(summarize(packets))


@api.get("/api/packets")
def packets():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    protocol = request.args.get("protocol")
    source = request.args.get("source")
    destination = request.args.get("destination")
    clauses = []
    args = []
    if protocol:
        clauses.append("protocol = ?")
        args.append(protocol.upper())
    if source:
        clauses.append("source_ip = ?")
        args.append(source)
    if destination:
        clauses.append("destination_ip = ?")
        args.append(destination)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    args.append(limit)
    with connect(current_app.config["DATABASE"]) as conn:
        return jsonify(_rows(conn, "SELECT * FROM packets" + where + " ORDER BY timestamp DESC LIMIT ?", tuple(args)))


@api.get("/api/alerts")
def alerts():
    status = request.args.get("status")
    query = "SELECT * FROM alerts"
    args = ()
    if status in {"open", "acknowledged", "resolved"}:
        query += " WHERE status = ?"
        args = (status,)
    query += " ORDER BY timestamp DESC LIMIT 500"
    with connect(current_app.config["DATABASE"]) as conn:
        return jsonify(_rows(conn, query, args))


@api.get("/api/alerts/<int:alert_id>")
def alert_detail(alert_id):
    with connect(current_app.config["DATABASE"]) as conn:
        rows = _rows(conn, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
    return (jsonify(rows[0]) if rows else (jsonify({"error": "alert not found"}), 404))


@api.post("/api/ingest")
def ingest():
    body = request.get_json(silent=True) or {}
    raw_packets = body.get("packets", [])
    if not isinstance(raw_packets, list) or len(raw_packets) > 1000:
        return jsonify({"error": "packets must be a list of at most 1000 items"}), 400
    try:
        packets = [normalize_packet(item, body.get("capture_source", "api")) for item in raw_packets]
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    with connect(current_app.config["DATABASE"]) as conn:
        conn.executemany("INSERT OR REPLACE INTO packets VALUES (:id,:timestamp,:source_ip,:destination_ip,:source_port,:destination_port,:protocol,:packet_size,:tcp_flags,:icmp_type,:icmp_code,:capture_source,:interface,:direction)", packets)
        for packet in packets:
            existing = conn.execute("""SELECT id,packet_count,byte_count,first_seen FROM flows
                                      WHERE source_ip=? AND destination_ip=? AND protocol=? 
                                      AND source_port IS ? AND destination_port IS ?""",
                                    (packet["source_ip"], packet["destination_ip"], packet["protocol"],
                                     packet["source_port"], packet["destination_port"])).fetchone()
            if existing:
                conn.execute("""UPDATE flows SET packet_count=?,byte_count=?,last_seen=? WHERE id=?""",
                             (existing["packet_count"] + 1, existing["byte_count"] + packet["packet_size"],
                              packet["timestamp"], existing["id"]))
            else:
                conn.execute("""INSERT INTO flows(source_ip,destination_ip,protocol,source_port,destination_port,packet_count,byte_count,first_seen,last_seen)
                                VALUES (?,?,?,?,?,?,?,?,?)""",
                             (packet["source_ip"], packet["destination_ip"], packet["protocol"],
                              packet["source_port"], packet["destination_port"], 1, packet["packet_size"],
                              packet["timestamp"], packet["timestamp"]))
        conn.execute("""INSERT INTO statistics(timestamp,total_packets,total_bytes,tcp_count,udp_count,icmp_count,packets_per_minute,bytes_per_minute)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (datetime.now(timezone.utc).isoformat(), len(packets),
                      sum(p["packet_size"] for p in packets),
                      sum(p["protocol"] == "TCP" for p in packets),
                      sum(p["protocol"] == "UDP" for p in packets),
                      sum(p["protocol"] == "ICMP" for p in packets),
                      len(packets), sum(p["packet_size"] for p in packets)))
        detections = DetectionEngine(current_app.config["THRESHOLDS"], current_app.config["TRUSTED_NETWORKS"]).detect(packets)
        for alert in detections:
            conn.execute("""INSERT INTO alerts(timestamp,severity,rule_name,source_ip,destination_ip,protocol,description,observed_value,threshold_value,time_window,packet_count,status)
                            VALUES (:timestamp,:severity,:rule_name,:source_ip,:destination_ip,:protocol,:description,:observed_value,:threshold_value,:time_window,:packet_count,:status)""", alert)
    return jsonify({"ingested": len(packets), "alerts": len(detections)}), 201


@api.post("/api/alerts/<int:alert_id>/<action>")
def update_alert(alert_id, action):
    status = {"acknowledge": "acknowledged", "resolve": "resolved"}.get(action)
    if not status:
        return jsonify({"error": "action must be acknowledge or resolve"}), 400
    with connect(current_app.config["DATABASE"]) as conn:
        cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        if cur.rowcount == 0:
            return jsonify({"error": "alert not found"}), 404
    return jsonify({"id": alert_id, "status": status})


@api.post("/api/agents/heartbeat")
def heartbeat():
    body = request.get_json(silent=True) or {}
    if not body.get("agent_id"):
        return jsonify({"error": "agent_id is required"}), 400
    from datetime import datetime, timezone
    with connect(current_app.config["DATABASE"]) as conn:
        conn.execute("INSERT OR REPLACE INTO agents(agent_id,last_seen,address,metadata) VALUES (?,?,?,?)",
                     (body["agent_id"], datetime.now(timezone.utc).isoformat(), request.remote_addr, json.dumps(body.get("metadata", {}))))
    return jsonify({"status": "accepted"})


@api.post("/api/monitoring/tcp")
@api.post("/api/monitoring/udp")
def monitoring_gateway():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    return ingest()


@api.get("/api/simulation")
def simulation():
    with connect(current_app.config["DATABASE"]) as conn:
        return jsonify(_rows(conn, "SELECT * FROM simulation_runs ORDER BY created_at DESC LIMIT 50"))


@api.get("/api/simulation/evidence")
def simulation_evidence():
    evidence = []
    for scenario in ("normal", "abnormal"):
        trace = Path("simulations") / "results" / f"{scenario}.tr"
        source = "ns2"
        if not trace.is_file():
            trace = Path("simulations") / f"sample_{scenario}.tr"
            source = "deterministic-fallback"
        if trace.is_file():
            evidence.append({"scenario": scenario, "source": source, "trace": str(trace),
                             "metrics": parse_trace(str(trace))})
    return jsonify(evidence)


@api.post("/api/simulation/load-generated")
def load_generated_simulations():
    imported = []
    for scenario in ("normal", "abnormal"):
        trace = Path("simulations") / "results" / f"{scenario}.tr"
        source = "ns2"
        if not trace.is_file():
            trace = Path("simulations") / f"sample_{scenario}.tr"
            source = "deterministic-fallback"
        if not trace.is_file():
            continue
        metrics = parse_trace(str(trace))
        packet_sent = metrics["packet_sent"]
        packet_received = metrics["packet_received"]
        packet_loss = metrics["packet_loss"]
        with connect(current_app.config["DATABASE"]) as conn:
            cursor = conn.execute("""INSERT INTO simulation_runs(name,scenario,source,packet_sent,packet_received,packet_loss,average_delay,created_at)
                                     VALUES (?,?,?,?,?,?,?,?)""",
                                  (f"{scenario} evidence", scenario, source, packet_sent, packet_received,
                                   packet_loss, 0, datetime.now(timezone.utc).isoformat()))
        imported.append({"id": cursor.lastrowid, "scenario": scenario})
    return jsonify({"imported": imported}), 201


@api.get("/api/realtime")
def realtime():
    def events():
        while True:
            with connect(current_app.config["DATABASE"]) as conn:
                packet_count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
                alert_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
                agent_count = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            payload = json.dumps({"packet_count": packet_count, "open_alerts": alert_count,
                                  "connected_agents": agent_count,
                                  "timestamp": datetime.now(timezone.utc).isoformat()})
            yield f"data: {payload}\n\n"
            time.sleep(5)
    return Response(stream_with_context(events()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@api.post("/api/simulation/import")
def import_simulation():
    body = request.get_json(silent=True) or {}
    required = {"scenario", "packet_sent", "packet_received", "packet_loss"}
    if not required.issubset(body):
        return jsonify({"error": "scenario, packet_sent, packet_received, and packet_loss are required"}), 400
    from datetime import datetime, timezone
    with connect(current_app.config["DATABASE"]) as conn:
        cur = conn.execute("""INSERT INTO simulation_runs(name,scenario,source,packet_sent,packet_received,packet_loss,average_delay,created_at)
                              VALUES (?,?,?,?,?,?,?,?)""",
                           (body.get("name", "imported"), body["scenario"], body.get("source", "ns2"),
                            body["packet_sent"], body["packet_received"], body["packet_loss"],
                            body.get("average_delay", 0), datetime.now(timezone.utc).isoformat()))
    return jsonify({"id": cur.lastrowid}), 201


@api.get("/api/simulation/<int:simulation_id>/results")
def simulation_results(simulation_id):
    with connect(current_app.config["DATABASE"]) as conn:
        rows = _rows(conn, "SELECT * FROM simulation_runs WHERE id = ?", (simulation_id,))
    return (jsonify(rows[0]) if rows else (jsonify({"error": "simulation not found"}), 404))


@api.post("/api/reports/generate")
def reports():
    with connect(current_app.config["DATABASE"]) as conn:
        packets = _rows(conn, "SELECT * FROM packets ORDER BY timestamp")
        alerts = _rows(conn, "SELECT * FROM alerts ORDER BY timestamp")
    paths = generate_reports(packets, alerts, current_app.config["REPORT_DIR"])
    with connect(current_app.config["DATABASE"]) as conn:
        report_ids = {}
        for kind, path in paths.items():
            cursor = conn.execute("INSERT INTO reports(kind,path,created_at) VALUES (?,?,datetime('now'))",
                                  (kind, path))
            report_ids[kind] = cursor.lastrowid
    paths["ids"] = report_ids
    return jsonify(paths), 201


@api.get("/api/reports")
def report_list():
    root = Path(current_app.config["REPORT_DIR"])
    return jsonify(sorted(path.name for path in root.glob("*") if path.is_file()))


@api.get("/api/reports/<path:filename>")
def download_report(filename):
    root = Path(current_app.config["REPORT_DIR"]).resolve()
    path = (root / filename).resolve()
    if root not in path.parents or not path.is_file():
        return jsonify({"error": "report not found"}), 404
    return send_file(path, as_attachment=True)


@api.get("/api/reports/<int:report_id>/download")
def download_report_by_id(report_id):
    with connect(current_app.config["DATABASE"]) as conn:
        rows = _rows(conn, "SELECT path FROM reports WHERE id = ?", (report_id,))
    if not rows:
        return jsonify({"error": "report not found"}), 404
    root = Path(current_app.config["REPORT_DIR"]).resolve()
    path = Path(rows[0]["path"]).resolve()
    if root not in path.parents or not path.is_file():
        return jsonify({"error": "report not found"}), 404
    return send_file(path, as_attachment=True)
