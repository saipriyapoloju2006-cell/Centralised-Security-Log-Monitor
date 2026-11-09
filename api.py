"""
REST API endpoints implementation using Starlette ASGI framework.
Provides routes for ingestion, search, alerts, incident management, simulation, and reports.
"""
import json
import csv
import io
import os
import zipfile
import logging
from pathlib import Path
from datetime import datetime, timezone
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, PlainTextResponse, FileResponse
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from app.config import STATIC_DIR, BASE_DIR
from app.database import init_db, get_db, row_to_dict, rows_to_dicts
from app.normalizer import normalize_log_entry, parse_multiline_logs
from app.detection_engine import DetectionEngine
from app.incident_manager import IncidentManager
from app.simulator import AttackSimulator

logger = logging.getLogger(__name__)

engine = DetectionEngine()

def ingest_single_event(event_data: dict) -> list:
    """Helper to persist a normalized event and evaluate rules."""
    normalized = normalize_log_entry(event_data)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO events (
                timestamp, source_ip, destination_ip, hostname, username,
                event_type, action, severity, source_system, message,
                raw_log, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized["timestamp"],
                normalized.get("source_ip"),
                normalized.get("destination_ip"),
                normalized.get("hostname"),
                normalized.get("username"),
                normalized["event_type"],
                normalized.get("action", "UNKNOWN"),
                normalized.get("severity", "INFO"),
                normalized.get("source_system", "generic"),
                normalized.get("message"),
                normalized.get("raw_log"),
                json.dumps(normalized.get("metadata", {})),
                normalized["created_at"]
            )
        )
        event_id = cursor.lastrowid

    # Evaluate event against rules
    alerts = engine.evaluate_event(event_id, normalized)
    return alerts

simulator = AttackSimulator(ingest_callback=ingest_single_event)

# ---------------- API HANDLERS ----------------

async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

async def ingest_logs(request: Request) -> JSONResponse:
    """Ingest single or batch log entries."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    entries = body if isinstance(body, list) else [body]
    total_ingested = 0
    all_alerts = []

    for entry in entries:
        alerts = ingest_single_event(entry)
        if alerts:
            all_alerts.extend(alerts)
        total_ingested += 1

    return JSONResponse({
        "status": "success",
        "ingested_count": total_ingested,
        "alerts_triggered": len(all_alerts),
        "alerts": all_alerts
    })

async def upload_log_file(request: Request) -> JSONResponse:
    """Upload raw log text file or multipart payload."""
    try:
        form = await request.form()
        if "file" in form:
            upload_file = form["file"]
            content_bytes = await upload_file.read()
            text_data = content_bytes.decode("utf-8", errors="replace")
        elif "raw_text" in form:
            text_data = str(form["raw_text"])
        else:
            body_bytes = await request.body()
            text_data = body_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return JSONResponse({"error": f"Failed reading upload: {str(e)}"}, status_code=400)

    normalized_events = parse_multiline_logs(text_data)
    total_ingested = 0
    all_alerts = []

    for ev in normalized_events:
        alerts = ingest_single_event(ev)
        if alerts:
            all_alerts.extend(alerts)
        total_ingested += 1

    return JSONResponse({
        "status": "success",
        "lines_parsed": total_ingested,
        "alerts_triggered": len(all_alerts),
        "alerts": all_alerts
    })

async def list_logs(request: Request) -> JSONResponse:
    """Search and filter logs with pagination."""
    params = request.query_params
    q = params.get("q", "").strip()
    source_ip = params.get("source_ip", "").strip()
    username = params.get("username", "").strip()
    hostname = params.get("hostname", "").strip()
    event_type = params.get("event_type", "").strip()
    severity = params.get("severity", "").strip()
    start_time = params.get("start_time", "").strip()
    end_time = params.get("end_time", "").strip()

    limit = min(int(params.get("limit", 50)), 500)
    offset = max(int(params.get("offset", 0)), 0)

    where_clauses = ["1=1"]
    sql_params = []

    if q:
        where_clauses.append("(message LIKE ? OR raw_log LIKE ? OR username LIKE ? OR source_ip LIKE ? OR hostname LIKE ?)")
        like_term = f"%{q}%"
        sql_params.extend([like_term, like_term, like_term, like_term, like_term])
    if source_ip:
        where_clauses.append("source_ip = ?")
        sql_params.append(source_ip)
    if username:
        where_clauses.append("username = ?")
        sql_params.append(username)
    if hostname:
        where_clauses.append("hostname = ?")
        sql_params.append(hostname)
    if event_type:
        where_clauses.append("event_type = ?")
        sql_params.append(event_type.upper())
    if severity:
        where_clauses.append("severity = ?")
        sql_params.append(severity.upper())
    if start_time:
        where_clauses.append("timestamp >= ?")
        sql_params.append(start_time)
    if end_time:
        where_clauses.append("timestamp <= ?")
        sql_params.append(end_time)

    where_str = " AND ".join(where_clauses)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) as total FROM events WHERE {where_str}", sql_params)
        total_count = cursor.fetchone()["total"]

        query = f"""
            SELECT * FROM events
            WHERE {where_str}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, sql_params + [limit, offset])
        rows = rows_to_dicts(cursor.fetchall())

    return JSONResponse({
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": rows
    })

async def get_dashboard_stats(request: Request) -> JSONResponse:
    """Summary statistics for dashboards."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Total Events
        cursor.execute("SELECT COUNT(*) as total FROM events")
        total_events = cursor.fetchone()["total"]

        # 2. Total Alerts & By Severity
        cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
        alert_counts_by_sev = {row["severity"]: row["count"] for row in cursor.fetchall()}
        total_alerts = sum(alert_counts_by_sev.values())

        # 3. Active (Unresolved) Alerts
        cursor.execute("SELECT COUNT(*) as active FROM alerts WHERE status IN ('NEW', 'ACKNOWLEDGED', 'IN_PROGRESS')")
        active_alerts = cursor.fetchone()["active"]

        # 4. Total and Open Incidents
        cursor.execute("SELECT COUNT(*) as total FROM incidents")
        total_incidents = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) as open_inc FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')")
        open_incidents = cursor.fetchone()["open_inc"]

        # 5. Events breakdown by type
        cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC LIMIT 8")
        event_types = rows_to_dicts(cursor.fetchall())

        # 6. Top 5 Offending Source IPs
        cursor.execute(
            """
            SELECT source_ip, COUNT(*) as count FROM events
            WHERE source_ip IS NOT NULL AND source_ip NOT IN ('0.0.0.0', '127.0.0.1')
            GROUP BY source_ip ORDER BY count DESC LIMIT 5
            """
        )
        top_ips = rows_to_dicts(cursor.fetchall())

        # 7. Top 5 Targeted Users
        cursor.execute(
            """
            SELECT username, COUNT(*) as count FROM events
            WHERE username IS NOT NULL AND username != ''
            GROUP BY username ORDER BY count DESC LIMIT 5
            """
        )
        top_users = rows_to_dicts(cursor.fetchall())

        # 8. Recent 10 Alerts
        cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10")
        recent_alerts = rows_to_dicts(cursor.fetchall())

    return JSONResponse({
        "total_events": total_events,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "alerts_by_severity": {
            "CRITICAL": alert_counts_by_sev.get("CRITICAL", 0),
            "HIGH": alert_counts_by_sev.get("HIGH", 0),
            "MEDIUM": alert_counts_by_sev.get("MEDIUM", 0),
            "LOW": alert_counts_by_sev.get("LOW", 0)
        },
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "event_types": event_types,
        "top_ips": top_ips,
        "top_users": top_users,
        "recent_alerts": recent_alerts
    })

async def list_alerts(request: Request) -> JSONResponse:
    """List alerts with optional status/severity filters."""
    params = request.query_params
    status = params.get("status")
    severity = params.get("severity")
    limit = min(int(params.get("limit", 100)), 500)

    where_clauses = ["1=1"]
    sql_params = []
    if status:
        where_clauses.append("status = ?")
        sql_params.append(status.upper())
    if severity:
        where_clauses.append("severity = ?")
        sql_params.append(severity.upper())

    query = f"SELECT * FROM alerts WHERE {' AND '.join(where_clauses)} ORDER BY created_at DESC LIMIT ?"
    sql_params.append(limit)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, sql_params)
        alerts = rows_to_dicts(cursor.fetchall())

    return JSONResponse({"alerts": alerts})

async def get_alert_detail(request: Request) -> JSONResponse:
    """Fetch an alert and its correlated events."""
    alert_id = int(request.path_params["id"])
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        alert = row_to_dict(cursor.fetchone())
        if not alert:
            return JSONResponse({"error": "Alert not found"}, status_code=404)

        # Get matched events
        cursor.execute(
            """
            SELECT e.* FROM events e
            JOIN alert_events ae ON e.id = ae.event_id
            WHERE ae.alert_id = ?
            ORDER BY e.timestamp ASC
            """,
            (alert_id,)
        )
        alert["events"] = rows_to_dicts(cursor.fetchall())

        # Get rule metadata
        cursor.execute("SELECT * FROM rules WHERE id = ?", (alert.get("rule_id"),))
        alert["rule"] = row_to_dict(cursor.fetchone())

    return JSONResponse(alert)

async def update_alert(request: Request) -> JSONResponse:
    """Update alert status (e.g. ACKNOWLEDGED, RESOLVED)."""
    alert_id = int(request.path_params["id"])
    body = await request.json()
    new_status = body.get("status", "").upper()
    now_iso = datetime.now(timezone.utc).isoformat()
    resolved_at = now_iso if new_status in ("RESOLVED", "FALSE_POSITIVE") else None

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alerts
            SET status = ?, resolved_at = COALESCE(?, resolved_at)
            WHERE id = ?
            """,
            (new_status, resolved_at, alert_id)
        )
        if cursor.rowcount == 0:
            return JSONResponse({"error": "Alert not found"}, status_code=404)

        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        updated = row_to_dict(cursor.fetchone())

    return JSONResponse(updated)

async def list_incidents(request: Request) -> JSONResponse:
    """List all incidents."""
    params = request.query_params
    status = params.get("status")
    severity = params.get("severity")
    incidents = IncidentManager.list_incidents(status=status, severity=severity)
    return JSONResponse({"incidents": incidents})

async def create_incident(request: Request) -> JSONResponse:
    """Manually create incident and link alerts."""
    body = await request.json()
    title = body.get("title")
    if not title:
        return JSONResponse({"error": "Title is required"}, status_code=400)
    
    desc = body.get("description", "")
    sev = body.get("severity", "HIGH")
    assigned = body.get("assigned_to", "Lead Analyst")
    alert_ids = body.get("alert_ids", [])

    incident = IncidentManager.create_incident(
        title=title, description=desc, severity=sev, assigned_to=assigned, alert_ids=alert_ids
    )
    return JSONResponse(incident, status_code=201)

async def get_incident_detail(request: Request) -> JSONResponse:
    """Fetch incident detail, notes, alerts, and correlated timeline."""
    inc_id = int(request.path_params["id"])
    detail = IncidentManager.get_incident_details(inc_id)
    if not detail:
        return JSONResponse({"error": "Incident not found"}, status_code=404)
    return JSONResponse(detail)

async def update_incident(request: Request) -> JSONResponse:
    """Update incident status, assignee, or resolution."""
    inc_id = int(request.path_params["id"])
    body = await request.json()
    updated = IncidentManager.update_incident(inc_id, body)
    if not updated:
        return JSONResponse({"error": "Incident not found"}, status_code=404)
    return JSONResponse(updated)

async def add_incident_note(request: Request) -> JSONResponse:
    """Add analyst investigation note."""
    inc_id = int(request.path_params["id"])
    body = await request.json()
    note_text = body.get("note", "").strip()
    author = body.get("author", "Analyst").strip()

    if not note_text:
        return JSONResponse({"error": "Note text cannot be empty"}, status_code=400)

    created_note = IncidentManager.add_note(inc_id, author, note_text)
    return JSONResponse(created_note, status_code=201)

async def list_rules(request: Request) -> JSONResponse:
    """List all detection rules."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules ORDER BY id ASC")
        rules = rows_to_dicts(cursor.fetchall())
        for r in rules:
            if r.get("parameters_json"):
                try:
                    r["parameters"] = json.loads(r["parameters_json"])
                except Exception:
                    r["parameters"] = {}
    return JSONResponse({"rules": rules})

async def update_rule(request: Request) -> JSONResponse:
    """Update detection rule configuration."""
    rule_id = int(request.path_params["id"])
    body = await request.json()
    now_iso = datetime.now(timezone.utc).isoformat()

    updates = []
    params = []

    if "enabled" in body:
        updates.append("enabled = ?")
        params.append(1 if body["enabled"] else 0)
    if "window_seconds" in body:
        updates.append("window_seconds = ?")
        params.append(int(body["window_seconds"]))
    if "threshold_count" in body:
        updates.append("threshold_count = ?")
        params.append(int(body["threshold_count"]))
    if "severity" in body:
        updates.append("severity = ?")
        params.append(body["severity"].upper())

    if not updates:
        return JSONResponse({"error": "No valid fields to update"}, status_code=400)

    updates.append("updated_at = ?")
    params.append(now_iso)
    params.append(rule_id)

    with get_db() as conn:
        cursor = conn.cursor()
        query = f"UPDATE rules SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        if cursor.rowcount == 0:
            return JSONResponse({"error": "Rule not found"}, status_code=404)
        cursor.execute("SELECT * FROM rules WHERE id = ?", (rule_id,))
        updated = row_to_dict(cursor.fetchone())

    return JSONResponse(updated)

async def run_simulation(request: Request) -> JSONResponse:
    """Execute a simulated security attack or normal test scenario."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    scenario = body.get("scenario", "brute_force")
    intensity = int(body.get("intensity", 5))
    target_ip = body.get("target_ip")
    target_user = body.get("target_user")

    try:
        result = simulator.run_scenario(
            scenario=scenario,
            intensity=intensity,
            target_ip=target_ip,
            target_user=target_user
        )
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

async def get_summary_report(request: Request) -> JSONResponse:
    """Generates an executive security posture and incident response report."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total_events FROM events")
        total_events = cursor.fetchone()["total_events"]

        cursor.execute("SELECT COUNT(*) as total_alerts FROM alerts")
        total_alerts = cursor.fetchone()["total_alerts"]

        cursor.execute("SELECT COUNT(*) as total_incidents FROM incidents")
        total_incidents = cursor.fetchone()["total_incidents"]

        cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
        alerts_by_sev = {r["severity"]: r["cnt"] for r in cursor.fetchall()}

        cursor.execute("SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status")
        incidents_by_status = {r["status"]: r["cnt"] for r in cursor.fetchall()}

        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 5")
        top_incidents = rows_to_dicts(cursor.fetchall())

        cursor.execute(
            """
            SELECT source_ip, COUNT(*) as count FROM events
            WHERE source_ip IS NOT NULL AND source_ip NOT IN ('0.0.0.0', '127.0.0.1')
            GROUP BY source_ip ORDER BY count DESC LIMIT 5
            """
        )
        top_threat_sources = rows_to_dicts(cursor.fetchall())

    return JSONResponse({
        "report_title": "Executive Cybersecurity Monitoring & Alert Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events_analyzed": total_events,
            "security_alerts_generated": total_alerts,
            "formal_incidents_recorded": total_incidents,
            "threat_distribution": alerts_by_sev,
            "incident_lifecycle_distribution": incidents_by_status
        },
        "critical_incidents": top_incidents,
        "top_threat_actors": top_threat_sources,
        "recommendations": [
            "Implement automated IP blocking for IPs triggering RULE-001 (Brute Force).",
            "Enforce Multi-Factor Authentication (MFA) immediately for accounts flagged under RULE-002 (Account Compromise).",
            "Audit root/sudo privileges and restrict off-hours administrative access (RULE-004).",
            "Review perimeter firewall rules to block port scans from flagged subnets."
        ]
    })

async def export_logs_csv(request: Request) -> Response:
    """Export recent events as a downloadable CSV."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, source_ip, destination_ip, hostname, username, event_type, action, severity, source_system, message FROM events ORDER BY id DESC LIMIT 2000")
        rows = rows_to_dicts(cursor.fetchall())

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write("id,timestamp,source_ip,destination_ip,hostname,username,event_type,action,severity,source_system,message\n")

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_events.csv"}
    )

async def export_alerts_csv(request: Request) -> Response:
    """Export alerts as CSV."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, rule_code, title, severity, status, source_ip, hostname, username, matched_events_count, first_event_time, last_event_time, created_at FROM alerts ORDER BY id DESC")
        rows = rows_to_dicts(cursor.fetchall())

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write("id,rule_code,title,severity,status,source_ip,hostname,username,matched_events_count,first_event_time,last_event_time,created_at\n")

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_alerts.csv"}
    )

async def reset_database(request: Request) -> JSONResponse:
    """Clear events, alerts, and incidents for fresh testing demonstrations."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alert_events")
        cursor.execute("DELETE FROM incident_notes")
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM events")
    return JSONResponse({"status": "success", "message": "Database cleared and reset for new testing."})

async def download_project_zip(request: Request) -> Response:
    """Dynamically packages the current project into a ZIP and returns it as a file download."""
    zip_path = BASE_DIR.parent / "centralized_security_log_monitor.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(BASE_DIR):
            if '__pycache__' in root:
                continue
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(BASE_DIR.parent)
                zipf.write(file_path, arcname)

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename="centralized_security_log_monitor.zip"
    )


def create_app() -> Starlette:
    """Application factory for Starlette."""
    init_db()

    routes = [
        Route("/api/health", health_check, methods=["GET"]),
        Route("/api/logs/ingest", ingest_logs, methods=["POST"]),
        Route("/api/logs/upload", upload_log_file, methods=["POST"]),
        Route("/api/logs", list_logs, methods=["GET"]),
        Route("/api/logs/stats", get_dashboard_stats, methods=["GET"]),
        Route("/api/alerts", list_alerts, methods=["GET"]),
        Route("/api/alerts/{id:int}", get_alert_detail, methods=["GET"]),
        Route("/api/alerts/{id:int}", update_alert, methods=["PATCH"]),
        Route("/api/incidents", list_incidents, methods=["GET"]),
        Route("/api/incidents", create_incident, methods=["POST"]),
        Route("/api/incidents/{id:int}", get_incident_detail, methods=["GET"]),
        Route("/api/incidents/{id:int}", update_incident, methods=["PATCH"]),
        Route("/api/incidents/{id:int}/notes", add_incident_note, methods=["POST"]),
        Route("/api/rules", list_rules, methods=["GET"]),
        Route("/api/rules/{id:int}", update_rule, methods=["PATCH"]),
        Route("/api/simulator/run", run_simulation, methods=["POST"]),
        Route("/api/reports/summary", get_summary_report, methods=["GET"]),
        Route("/api/export/logs", export_logs_csv, methods=["GET"]),
        Route("/api/export/alerts", export_alerts_csv, methods=["GET"]),
        Route("/api/system/reset", reset_database, methods=["POST"]),
        Route("/api/download/project", download_project_zip, methods=["GET"]),
        Mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    ]

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )
    ]

    return Starlette(debug=True, routes=routes, middleware=middleware)
