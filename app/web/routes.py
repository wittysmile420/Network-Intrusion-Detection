import json
import sqlite3
from pathlib import Path
from flask import Blueprint, current_app, jsonify, render_template, request, send_file

from ..analysis.statistics import summarize
from ..capture.packet_processor import normalize_packet
from ..database import connect
from ..detection.engine import DetectionEngine
from ..reporting.report_service import generate_reports

api = Blueprint("api", __name__, template_folder="templates", static_folder="static")


def _rows(conn, query, args=()):
    return [dict(row) for row in conn.execute(query, args).fetchall()]


@api.get("/")
def dashboard():
    return render_template("dashboard.html")


@api.get("/api/health")
def health():
    return jsonify({"status": "ok", "privacy_mode": current_app.config["PRIVACY_MODE"]})


@api.get("/api/dashboard")
def dashboard_data():
    with connect(current_app.config["DATABASE"]) as conn:
        packets = _rows(conn, "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 500")
        alerts = _rows(conn, "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
    return jsonify({"statistics": summarize(packets), "packets": packets[:20], "alerts": alerts,
                    "capture": {"source": current_app.config["CAPTURE_SOURCE"], "interface": current_app.config["CAPTURE_INTERFACE"]}})


@api.get("/api/statistics")
def statistics():
    with connect(current_app.config["DATABASE"]) as conn:
        packets = _rows(conn, "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 5000")
    return jsonify(summarize(packets))


@api.get("/api/packets")
def packets():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    with connect(current_app.config["DATABASE"]) as conn:
        return jsonify(_rows(conn, "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,)))


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
