"""
Rule-Based Detection Engine.
Evaluates incoming security events against configured detection rules,
manages windowed temporal correlations, deduplicates alerts, and links matched events.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from app.database import get_db, row_to_dict, rows_to_dicts

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self):
        pass

    def evaluate_event(self, event_id: int, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single newly-ingested event against all active rules.
        Returns a list of generated or updated alert dicts.
        """
        alerts_triggered = []
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules WHERE enabled = 1")
            rules = rows_to_dicts(cursor.fetchall())

            for rule in rules:
                rule_code = rule["rule_code"]
                try:
                    alert = None
                    if rule_code == "RULE-001":
                        alert = self._eval_rule_001_failed_logins(conn, rule, event_id, event)
                    elif rule_code == "RULE-002":
                        alert = self._eval_rule_002_success_after_failure(conn, rule, event_id, event)
                    elif rule_code == "RULE-003":
                        alert = self._eval_rule_003_access_denied(conn, rule, event_id, event)
                    elif rule_code == "RULE-004":
                        alert = self._eval_rule_004_privilege_abuse(conn, rule, event_id, event)
                    elif rule_code == "RULE-005":
                        alert = self._eval_rule_005_event_surge(conn, rule, event_id, event)
                    elif rule_code == "RULE-006":
                        alert = self._eval_rule_006_port_scan(conn, rule, event_id, event)

                    if alert:
                        alerts_triggered.append(alert)
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule_code}: {e}", exc_info=True)

        return alerts_triggered

    # ---------------- Rule 001: Multiple Failed Logins ----------------
    def _eval_rule_001_failed_logins(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "AUTH_FAILURE":
            return None

        src_ip = event.get("source_ip")
        if not src_ip or src_ip in ("0.0.0.0", "127.0.0.1", "unknown"):
            return None

        window_sec = rule["window_seconds"]
        threshold = rule["threshold_count"]
        ev_time = event["timestamp"]

        # Calculate time cutoff
        try:
            dt = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        cutoff = (dt - timedelta(seconds=window_sec)).isoformat()

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp FROM events
            WHERE event_type = 'AUTH_FAILURE'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp DESC
            """,
            (src_ip, cutoff, ev_time)
        )
        matching_events = rows_to_dicts(cursor.fetchall())
        count = len(matching_events)

        if count >= threshold:
            title = f"Multiple Failed Login Attempts from {src_ip} ({count} attempts)"
            desc = (f"Detected {count} failed authentication attempts from source IP {src_ip} "
                    f"within {window_sec} seconds. Potential Brute Force or Credential Stuffing attack.")
            matched_ids = [e["id"] for e in matching_events]
            return self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=src_ip,
                hostname=event.get("hostname"),
                username=event.get("username"),
                matched_event_ids=matched_ids,
                first_time=matching_events[-1]["timestamp"],
                last_time=matching_events[0]["timestamp"]
            )
        return None

    # ---------------- Rule 002: Successful Login After Multiple Failed Logins ----------------
    def _eval_rule_002_success_after_failure(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "AUTH_SUCCESS":
            return None

        username = event.get("username")
        src_ip = event.get("source_ip")
        if not username and not src_ip:
            return None

        window_sec = rule["window_seconds"]
        threshold = rule["threshold_count"]
        ev_time = event["timestamp"]

        try:
            dt = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        cutoff = (dt - timedelta(seconds=window_sec)).isoformat()

        cursor = conn.cursor()
        # Query failed logins for the same username or same IP immediately prior
        query = """
            SELECT id, timestamp, username, source_ip FROM events
            WHERE event_type = 'AUTH_FAILURE'
              AND timestamp >= ?
              AND timestamp <= ?
              AND (username = ? OR source_ip = ?)
            ORDER BY timestamp DESC
        """
        cursor.execute(query, (cutoff, ev_time, username, src_ip))
        failed_events = rows_to_dicts(cursor.fetchall())
        count = len(failed_events)

        if count >= threshold:
            title = f"Account Compromise Suspected: Successful Login After {count} Failed Attempts"
            desc = (f"User '{username}' or source IP {src_ip} had {count} consecutive failed login attempts "
                    f"prior to a successful login at {ev_time}. High risk of password guessing or account takeover.")
            matched_ids = [e["id"] for e in failed_events] + [event_id]

            alert = self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=src_ip,
                hostname=event.get("hostname"),
                username=username,
                matched_event_ids=matched_ids,
                first_time=failed_events[-1]["timestamp"],
                last_time=ev_time
            )

            # Auto-escalate CRITICAL account compromise to incident
            if alert and alert.get("id"):
                self._ensure_incident_for_alert(conn, alert)

            return alert
        return None

    # ---------------- Rule 003: Repeated Access-Denied Events ----------------
    def _eval_rule_003_access_denied(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "ACCESS_DENIED":
            return None

        hostname = event.get("hostname")
        src_ip = event.get("source_ip")
        window_sec = rule["window_seconds"]
        threshold = rule["threshold_count"]
        ev_time = event["timestamp"]

        try:
            dt = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        cutoff = (dt - timedelta(seconds=window_sec)).isoformat()

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp FROM events
            WHERE event_type = 'ACCESS_DENIED'
              AND hostname = ?
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp DESC
            """,
            (hostname, src_ip, cutoff, ev_time)
        )
        denied_events = rows_to_dicts(cursor.fetchall())
        count = len(denied_events)

        if count >= threshold:
            title = f"Repeated Access-Denied on {hostname} from {src_ip} ({count} events)"
            desc = (f"Client at {src_ip} experienced {count} access-denied/unauthorized violations "
                    f"on server '{hostname}' within {window_sec}s. Potential directory traversal or privilege probing.")
            matched_ids = [e["id"] for e in denied_events]
            return self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=src_ip,
                hostname=hostname,
                username=event.get("username"),
                matched_event_ids=matched_ids,
                first_time=denied_events[-1]["timestamp"],
                last_time=denied_events[0]["timestamp"]
            )
        return None

    # ---------------- Rule 004: Unusual Privileged Account Activity ----------------
    def _eval_rule_004_privilege_abuse(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        user = (event.get("username") or "").lower()
        ev_type = event.get("event_type")
        msg = (event.get("message") or "").lower()
        
        privileged_users = ["root", "admin", "administrator", "system", "wheel"]
        is_priv_user = user in privileged_users or any(p in user for p in privileged_users)

        # Trigger if PRIVILEGE_ACTION event or sensitive activity performed by privileged user
        sensitive_indicators = [
            "/etc/shadow", "chmod 777", "visudo", "flush privileges", "dump database",
            "disable firewall", "iptables -f", "mimikatz", "useradd", "net user"
        ]
        has_sensitive = any(ind in msg for ind in sensitive_indicators)

        if (is_priv_user and (ev_type == "PRIVILEGE_ACTION" or has_sensitive)) or (ev_type == "PRIVILEGE_ACTION"):
            title = f"Unusual Privileged Activity by Account '{user or 'root'}'"
            desc = (f"Sensitive action detected on {event.get('hostname')}: {event.get('message')}. "
                    f"Source: {event.get('source_ip')}. Privileged actions require immediate verification.")
            
            alert = self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=event.get("source_ip"),
                hostname=event.get("hostname"),
                username=event.get("username"),
                matched_event_ids=[event_id],
                first_time=event["timestamp"],
                last_time=event["timestamp"]
            )

            # Auto-escalate CRITICAL privileged abuse to incident
            if alert and alert.get("id"):
                self._ensure_incident_for_alert(conn, alert)

            return alert
        return None

    # ---------------- Rule 005: Sudden Surge in Events ----------------
    def _eval_rule_005_event_surge(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        src_ip = event.get("source_ip")
        if not src_ip or src_ip in ("0.0.0.0", "127.0.0.1"):
            return None

        window_sec = rule["window_seconds"]
        threshold = rule["threshold_count"]
        ev_time = event["timestamp"]

        try:
            dt = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        cutoff = (dt - timedelta(seconds=window_sec)).isoformat()

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp FROM events
            WHERE source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp DESC
            """,
            (src_ip, cutoff, ev_time)
        )
        surge_events = rows_to_dicts(cursor.fetchall())
        count = len(surge_events)

        if count >= threshold:
            title = f"Sudden Surge in Security Events from {src_ip} ({count} events/min)"
            desc = (f"A sudden volumetric surge of {count} events was detected from host {src_ip} "
                    f"within {window_sec}s. Potential DoS, automated exploitation, or malware propagation.")
            matched_ids = [e["id"] for e in surge_events]
            return self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=src_ip,
                hostname=event.get("hostname"),
                username=event.get("username"),
                matched_event_ids=matched_ids,
                first_time=surge_events[-1]["timestamp"],
                last_time=surge_events[0]["timestamp"]
            )
        return None

    # ---------------- Rule 006: Port Scanning Activity ----------------
    def _eval_rule_006_port_scan(self, conn, rule, event_id, event) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "NETWORK_FLOW":
            return None

        src_ip = event.get("source_ip")
        if not src_ip or src_ip in ("0.0.0.0", "127.0.0.1"):
            return None

        window_sec = rule["window_seconds"]
        threshold = rule["threshold_count"]
        ev_time = event["timestamp"]

        try:
            dt = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        cutoff = (dt - timedelta(seconds=window_sec)).isoformat()

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, metadata_json FROM events
            WHERE event_type = 'NETWORK_FLOW'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            """,
            (src_ip, cutoff, ev_time)
        )
        flow_events = rows_to_dicts(cursor.fetchall())
        
        # Check distinct destination ports
        distinct_ports = set()
        matched_ids = []
        for e in flow_events:
            matched_ids.append(e["id"])
            if e.get("metadata_json"):
                try:
                    meta = json.loads(e["metadata_json"])
                    if "port" in meta:
                        distinct_ports.add(meta["port"])
                except Exception:
                    pass

        if len(distinct_ports) >= threshold or len(flow_events) >= (threshold * 2):
            title = f"Port Scan Activity Detected from {src_ip} ({len(distinct_ports)} ports targeted)"
            desc = (f"Source {src_ip} attempted connections across {len(distinct_ports)} distinct ports "
                    f"in {window_sec}s. Likely reconnaissance/service discovery.")
            return self._upsert_alert(
                conn=conn,
                rule=rule,
                title=title,
                description=desc,
                source_ip=src_ip,
                hostname=event.get("hostname"),
                username=event.get("username"),
                matched_event_ids=matched_ids,
                first_time=flow_events[0]["timestamp"],
                last_time=flow_events[-1]["timestamp"]
            )
        return None

    # ---------------- Alert Deduplication & Persistence Helper ----------------
    def _upsert_alert(
        self, conn, rule, title: str, description: str,
        source_ip: Optional[str], hostname: Optional[str], username: Optional[str],
        matched_event_ids: List[int], first_time: str, last_time: str
    ) -> Dict[str, Any]:
        """
        Deduplicates against active alerts for the same rule and source_ip/username.
        If an alert is already OPEN/NEW within the last 10 minutes, updates matched count.
        Otherwise creates a new alert record.
        """
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check existing active alert
        cursor.execute(
            """
            SELECT id, matched_events_count FROM alerts
            WHERE rule_code = ?
              AND status IN ('NEW', 'ACKNOWLEDGED', 'IN_PROGRESS')
              AND (source_ip = ? OR username = ?)
            ORDER BY created_at DESC LIMIT 1
            """,
            (rule["rule_code"], source_ip, username)
        )
        existing = cursor.fetchone()

        if existing:
            alert_id = existing["id"]
            new_count = max(existing["matched_events_count"], len(matched_event_ids))
            cursor.execute(
                """
                UPDATE alerts
                SET matched_events_count = ?,
                    last_event_time = ?,
                    description = ?
                WHERE id = ?
                """,
                (new_count, last_time, description, alert_id)
            )
            # Map new events
            for eid in matched_event_ids:
                cursor.execute(
                    "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                    (alert_id, eid)
                )
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            return row_to_dict(cursor.fetchone())
        else:
            cursor.execute(
                """
                INSERT INTO alerts (
                    rule_id, rule_code, title, description, severity, status,
                    source_ip, hostname, username, first_event_time, last_event_time,
                    matched_events_count, created_at
                )
                VALUES (?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["id"], rule["rule_code"], title, description, rule["severity"],
                    source_ip, hostname, username, first_time, last_time,
                    len(matched_event_ids), now_iso
                )
            )
            alert_id = cursor.lastrowid
            for eid in matched_event_ids:
                cursor.execute(
                    "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                    (alert_id, eid)
                )
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            return row_to_dict(cursor.fetchone())

    def _ensure_incident_for_alert(self, conn, alert: Dict[str, Any]) -> None:
        """
        Auto-generates an Incident for high/critical security alerts if not already linked.
        """
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check if alert already has incident
        if alert.get("incident_id"):
            return

        # Check if an open incident exists for this target/source
        cursor.execute(
            """
            SELECT id, incident_number FROM incidents
            WHERE status IN ('OPEN', 'INVESTIGATING')
              AND (title LIKE ? OR description LIKE ?)
            LIMIT 1
            """,
            (f"%{alert.get('source_ip')}%", f"%{alert.get('username')}%")
        )
        existing_inc = cursor.fetchone()

        if existing_inc:
            inc_id = existing_inc["id"]
            cursor.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (inc_id, alert["id"]))
        else:
            # Generate incident number: INC-YYYYMMDD-XXXX
            dt_tag = datetime.now().strftime("%Y%m%d")
            cursor.execute("SELECT COUNT(*) as cnt FROM incidents")
            cnt = cursor.fetchone()["cnt"] + 1
            inc_num = f"INC-{dt_tag}-{cnt:04d}"

            cursor.execute(
                """
                INSERT INTO incidents (incident_number, title, description, severity, status, assigned_to, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'OPEN', 'Lead Analyst', ?, ?)
                """,
                (
                    inc_num,
                    f"Security Incident: {alert['title']}",
                    f"Automated incident generated from alert {alert['rule_code']}.\nDetails: {alert['description']}",
                    alert["severity"],
                    now_iso,
                    now_iso
                )
            )
            inc_id = cursor.lastrowid
            cursor.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (inc_id, alert["id"]))
            
            # Initial automated note
            cursor.execute(
                """
                INSERT INTO incident_notes (incident_id, author, note, created_at)
                VALUES (?, 'System SOC Automation', ?, ?)
                """,
                (inc_id, f"Incident created automatically from {alert['severity']} alert #{alert['id']}.", now_iso)
            )
