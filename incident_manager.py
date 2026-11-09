"""
Incident Management module.
Handles incident creation, assignment, notes, timeline tracking, and resolution workflow.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.database import get_db, row_to_dict, rows_to_dicts

class IncidentManager:
    @staticmethod
    def list_incidents(status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """List incidents with optional status or severity filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY created_at DESC"

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            incidents = rows_to_dicts(cursor.fetchall())
            
            # Fetch alert counts for each incident
            for inc in incidents:
                cursor.execute("SELECT COUNT(*) as alert_count FROM alerts WHERE incident_id = ?", (inc["id"],))
                inc["alert_count"] = cursor.fetchone()["alert_count"]
                cursor.execute("SELECT COUNT(*) as note_count FROM incident_notes WHERE incident_id = ?", (inc["id"],))
                inc["note_count"] = cursor.fetchone()["note_count"]
            return incidents

    @staticmethod
    def get_incident_details(incident_id: int) -> Optional[Dict[str, Any]]:
        """Fetch complete incident record with attached alerts and analyst notes."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            inc = row_to_dict(cursor.fetchone())
            if not inc:
                return None

            # Get linked alerts
            cursor.execute("SELECT * FROM alerts WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,))
            inc["alerts"] = rows_to_dicts(cursor.fetchall())

            # Get timeline notes
            cursor.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,))
            inc["notes"] = rows_to_dicts(cursor.fetchall())

            # Correlate all events from these alerts
            alert_ids = [a["id"] for a in inc["alerts"]]
            if alert_ids:
                placeholders = ",".join("?" for _ in alert_ids)
                cursor.execute(
                    f"""
                    SELECT DISTINCT e.* FROM events e
                    JOIN alert_events ae ON e.id = ae.event_id
                    WHERE ae.alert_id IN ({placeholders})
                    ORDER BY e.timestamp ASC
                    """,
                    alert_ids
                )
                inc["correlated_events"] = rows_to_dicts(cursor.fetchall())
            else:
                inc["correlated_events"] = []

            return inc

    @staticmethod
    def create_incident(title: str, description: str, severity: str, assigned_to: str, alert_ids: List[int]) -> Dict[str, Any]:
        """Manually create an incident and link specified alerts."""
        now_iso = datetime.now(timezone.utc).isoformat()
        dt_tag = datetime.now().strftime("%Y%m%d")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM incidents")
            cnt = cursor.fetchone()["cnt"] + 1
            inc_num = f"INC-{dt_tag}-{cnt:04d}"

            cursor.execute(
                """
                INSERT INTO incidents (incident_number, title, description, severity, status, assigned_to, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?)
                """,
                (inc_num, title, description, severity, assigned_to or "Unassigned", now_iso, now_iso)
            )
            inc_id = cursor.lastrowid

            # Link alerts
            for aid in alert_ids:
                cursor.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (inc_id, aid))

            # Initial note
            cursor.execute(
                """
                INSERT INTO incident_notes (incident_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (inc_id, assigned_to or "Analyst", f"Incident created manually with {len(alert_ids)} linked alerts.", now_iso)
            )

            cursor.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,))
            return row_to_dict(cursor.fetchone())

    @staticmethod
    def update_incident(incident_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update incident status, assigned analyst, or resolution notes."""
        now_iso = datetime.now(timezone.utc).isoformat()
        allowed_fields = ["title", "severity", "status", "assigned_to", "resolution_notes"]

        set_clauses = ["updated_at = ?"]
        params = [now_iso]

        for field in allowed_fields:
            if field in updates and updates[field] is not None:
                set_clauses.append(f"{field} = ?")
                params.append(updates[field])

        params.append(incident_id)

        with get_db() as conn:
            cursor = conn.cursor()
            query = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE id = ?"
            cursor.execute(query, params)

            if cursor.rowcount == 0:
                return None

            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            return row_to_dict(cursor.fetchone())

    @staticmethod
    def add_note(incident_id: int, author: str, note: str) -> Dict[str, Any]:
        """Add an analyst investigation note to the incident timeline."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO incident_notes (incident_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (incident_id, author, note, now_iso)
            )
            note_id = cursor.lastrowid
            
            # Touch incident updated_at
            cursor.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now_iso, incident_id))

            cursor.execute("SELECT * FROM incident_notes WHERE id = ?", (note_id,))
            return row_to_dict(cursor.fetchone())
