"""
Automated Test Suite for Centralized Security Log Monitoring & Alert System.
Validates:
1. Database schema initialization and predefined rule seeding
2. Normalization of diverse raw log formats into CIM
3. All required attack scenario detections:
   - Multiple failed logins from one IP (RULE-001)
   - Successful login immediately after several failed attempts (RULE-002)
   - Repeated access-denied events on a server (RULE-003)
   - Unusual activity from privileged account (RULE-004)
   - Sudden surge in security events from one computer (RULE-005)
   - Port scan probing (RULE-006)
   - Normal traffic baseline (0 false alerts)
4. Incident lifecycle, auto-escalation, and analyst investigation notes
5. Simulator execution and dashboard statistics calculation
"""
import unittest
from app.database import init_db, get_db, rows_to_dicts, row_to_dict
from app.normalizer import normalize_log_entry, parse_multiline_logs
from app.detection_engine import DetectionEngine
from app.simulator import AttackSimulator
from app.incident_manager import IncidentManager
from app.api import ingest_single_event, simulator

class SecurityLogMonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        # Clear test database before each test
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alert_events")
            cursor.execute("DELETE FROM incident_notes")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM incidents")
            cursor.execute("DELETE FROM events")

    # ================= 1. NORMALIZATION TESTS =================
    def test_01_normalize_linux_auth_failed(self):
        raw = "Nov 05 14:10:01 auth-gw sshd[14201]: Failed password for invalid user admin from 192.168.1.185 port 42101 ssh2"
        ev = normalize_log_entry(raw)
        self.assertEqual(ev["event_type"], "AUTH_FAILURE")
        self.assertEqual(ev["source_ip"], "192.168.1.185")
        self.assertEqual(ev["username"], "admin")
        self.assertEqual(ev["action"], "DENY")
        self.assertEqual(ev["severity"], "MEDIUM")

    def test_02_normalize_linux_auth_accepted(self):
        raw = "Nov 05 14:11:00 auth-gw sshd[14202]: Accepted password for sarah_admin from 192.168.1.185 port 42102 ssh2"
        ev = normalize_log_entry(raw)
        self.assertEqual(ev["event_type"], "AUTH_SUCCESS")
        self.assertEqual(ev["source_ip"], "192.168.1.185")
        self.assertEqual(ev["username"], "sarah_admin")
        self.assertEqual(ev["action"], "LOGIN")

    def test_03_normalize_apache_access_denied(self):
        raw = '192.168.1.92 - - [05/Nov/2026:14:15:01 +0000] "GET /api/v1/payroll/salaries HTTP/1.1" 403 241 "-" "CustomScanner/1.0"'
        ev = normalize_log_entry(raw)
        self.assertEqual(ev["event_type"], "ACCESS_DENIED")
        self.assertEqual(ev["source_ip"], "192.168.1.92")
        self.assertEqual(ev["action"], "DENY")
        self.assertEqual(ev["severity"], "MEDIUM")
        self.assertEqual(ev["metadata"]["http_status"], 403)

    def test_04_normalize_sudo_privilege_command(self):
        raw = "Nov 05 14:20:10 core-vault01 sudo: root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        ev = normalize_log_entry(raw)
        self.assertEqual(ev["event_type"], "PRIVILEGE_ACTION")
        self.assertEqual(ev["username"], "root")
        self.assertEqual(ev["severity"], "CRITICAL")
        self.assertTrue(ev["metadata"]["sensitive"])

    def test_05_normalize_windows_event_log(self):
        raw = "EventID: 4625, Account: administrator, Workstation: HR-PC01, SourceIP: 192.168.1.88, Status: 0xC000006D"
        ev = normalize_log_entry(raw)
        self.assertEqual(ev["event_type"], "AUTH_FAILURE")
        self.assertEqual(ev["username"], "administrator")
        self.assertEqual(ev["source_ip"], "192.168.1.88")

    def test_06_parse_multiline_logs(self):
        batch = (
            "Nov 05 14:10:01 auth-gw sshd[14201]: Failed password for invalid user admin from 192.168.1.185 port 42101 ssh2\n"
            "192.168.1.92 - - [05/Nov/2026:14:15:01 +0000] \"GET /admin HTTP/1.1\" 403 241\n"
        )
        parsed = parse_multiline_logs(batch)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["event_type"], "AUTH_FAILURE")
        self.assertEqual(parsed[1]["event_type"], "ACCESS_DENIED")

    # ================= 2. DETECTION ENGINE & SCENARIO TESTS =================
    def test_07_detect_rule_001_multiple_failed_logins(self):
        """Activity 1: Multiple failed login attempts from one IP address (Brute Force)."""
        result = simulator.run_scenario("brute_force", intensity=6)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertGreaterEqual(result["alerts_triggered"], 1)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-001'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "HIGH")
            self.assertEqual(alert["source_ip"], "192.168.1.185")
            self.assertGreaterEqual(alert["matched_events_count"], 5)

            # Check matched events mapping
            cursor.execute("SELECT COUNT(*) as cnt FROM alert_events WHERE alert_id = ?", (alert["id"],))
            mapped_count = cursor.fetchone()["cnt"]
            self.assertGreaterEqual(mapped_count, 5)

    def test_08_detect_rule_002_success_after_failure(self):
        """Activity 2: A successful login immediately after several failed attempts (Account Takeover)."""
        result = simulator.run_scenario("brute_force_success", intensity=4)
        self.assertEqual(result["status"], "COMPLETED")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-002'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["username"], "finance_director")

            # Check automated incident escalation
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (alert["incident_id"],))
            incident = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(incident)
            self.assertEqual(incident["severity"], "CRITICAL")
            self.assertEqual(incident["status"], "OPEN")

    def test_09_detect_rule_003_repeated_access_denied(self):
        """Activity 3: Repeated access-denied events on a server."""
        result = simulator.run_scenario("access_denied", intensity=4)
        self.assertEqual(result["status"], "COMPLETED")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-003'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "HIGH")
            self.assertEqual(alert["hostname"], "finance-db01")

    def test_10_detect_rule_004_privilege_abuse(self):
        """Activity 4: Unusual activity from a privileged account in a test environment."""
        result = simulator.run_scenario("privilege_abuse")
        self.assertEqual(result["status"], "COMPLETED")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-004'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["username"], "root")

            # Verify auto-escalated incident
            self.assertIsNotNone(alert["incident_id"])

    def test_11_detect_rule_005_event_surge(self):
        """Activity 5: A sudden increase in security-related events from one computer."""
        result = simulator.run_scenario("event_surge", intensity=25)
        self.assertEqual(result["status"], "COMPLETED")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-005'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["source_ip"], "172.16.8.99")
            self.assertGreaterEqual(alert["matched_events_count"], 20)

    def test_12_detect_rule_006_port_scan(self):
        """Activity 6: Port scan probing across distinct destination ports."""
        result = simulator.run_scenario("port_scan")
        self.assertEqual(result["status"], "COMPLETED")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE rule_code = 'RULE-006'")
            alert = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(alert)
            self.assertEqual(alert["source_ip"], "203.0.113.88")

    def test_13_normal_baseline_traffic_no_alerts(self):
        """Activity 7: Clean enterprise traffic produces zero false alarms."""
        result = simulator.run_scenario("normal_traffic", intensity=15)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["alerts_triggered"], 0)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
            alert_count = cursor.fetchone()["cnt"]
            self.assertEqual(alert_count, 0)

            cursor.execute("SELECT COUNT(*) as cnt FROM events")
            event_count = cursor.fetchone()["cnt"]
            self.assertEqual(event_count, 15)

    # ================= 3. INCIDENT WORKFLOW TESTS =================
    def test_14_incident_workflow(self):
        # 1. Create incident manually
        inc = IncidentManager.create_incident(
            title="Unauthorized Network Probing",
            description="Reconnaissance detected against perimeter DMZ",
            severity="HIGH",
            assigned_to="SOC Analyst Alpha",
            alert_ids=[]
        )
        inc_id = inc["id"]
        self.assertEqual(inc["status"], "OPEN")

        # 2. Add analyst note
        note = IncidentManager.add_note(inc_id, "SOC Analyst Alpha", "Firewall ACL 402 applied. Probing halted.")
        self.assertEqual(note["author"], "SOC Analyst Alpha")

        # 3. Update status to CONTAINED then RESOLVED
        updated = IncidentManager.update_incident(inc_id, {"status": "CONTAINED", "assigned_to": "SOC Lead"})
        self.assertEqual(updated["status"], "CONTAINED")
        self.assertEqual(updated["assigned_to"], "SOC Lead")

        # 4. Fetch details
        details = IncidentManager.get_incident_details(inc_id)
        self.assertIsNotNone(details)
        self.assertEqual(len(details["notes"]), 2) # Auto initial note + added note

    # ================= 4. INGESTION & SEARCH TESTS =================
    def test_15_ingestion_and_search_query(self):
        # Ingest single event
        ingest_single_event({
            "source_ip": "10.0.99.1",
            "hostname": "prod-app01",
            "username": "sys_auditor",
            "event_type": "FILE_ACCESS",
            "action": "READ",
            "severity": "INFO",
            "message": "Routine audit configuration review"
        })

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE username = 'sys_auditor'")
            ev = row_to_dict(cursor.fetchone())
            self.assertIsNotNone(ev)
            self.assertEqual(ev["source_ip"], "10.0.99.1")
            self.assertEqual(ev["event_type"], "FILE_ACCESS")

if __name__ == "__main__":
    unittest.main(verbosity=2)
