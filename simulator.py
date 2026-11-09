"""
Simulation and Test Environment Module.
Generates controlled, authorized security test scenarios corresponding directly to
the problem statement requirements:
1. Multiple failed login attempts from one IP (Brute Force)
2. Successful login immediately after several failed attempts (Compromise / Account Takeover)
3. Repeated access-denied events on a server (Privilege / Directory Probing)
4. Unusual activity from a privileged account in a test environment (Privilege Abuse)
5. Sudden surge in security-related events from one computer (Volumetric Anomaly)
6. Port scan reconnaissance
7. Normal enterprise baseline traffic
"""
import time
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

class AttackSimulator:
    def __init__(self, ingest_callback):
        """
        ingest_callback is a function(event_dict) that persists and evaluates the event.
        """
        self.ingest_callback = ingest_callback

    def run_scenario(self, scenario: str, intensity: int = 5, target_ip: str = None, target_user: str = None) -> Dict[str, Any]:
        """Execute selected scenario and return execution summary."""
        scenario = scenario.lower()
        if scenario == "brute_force":
            return self._simulate_brute_force(intensity, target_ip, target_user)
        elif scenario == "brute_force_success":
            return self._simulate_brute_force_success(intensity, target_ip, target_user)
        elif scenario == "access_denied":
            return self._simulate_access_denied(intensity, target_ip)
        elif scenario == "privilege_abuse":
            return self._simulate_privilege_abuse(target_user)
        elif scenario == "event_surge":
            return self._simulate_event_surge(intensity or 25, target_ip)
        elif scenario == "port_scan":
            return self._simulate_port_scan(target_ip)
        elif scenario == "normal_traffic":
            return self._simulate_normal_traffic(intensity or 15)
        elif scenario == "comprehensive_suite":
            return self._simulate_comprehensive_suite()
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

    # Scenario 1: Multiple Failed Logins
    def _simulate_brute_force(self, count: int = 6, src_ip: str = None, user: str = None) -> Dict[str, Any]:
        src_ip = src_ip or "192.168.1.185"
        user = user or "sarah_admin"
        now = datetime.now(timezone.utc)
        events_sent = 0
        all_alerts = []

        for i in range(max(count, 6)):
            ts = (now - timedelta(seconds=(count - i) * 10)).isoformat()
            raw = f"Failed password for user {user} from {src_ip} port {45000 + i} ssh2"
            event = {
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": "10.0.0.15",
                "hostname": "ssh-gw-01",
                "username": user,
                "event_type": "AUTH_FAILURE",
                "action": "DENY",
                "severity": "MEDIUM",
                "source_system": "linux_auth",
                "message": f"Failed password for invalid/locked user {user} from {src_ip}",
                "raw_log": raw,
                "metadata": {"attempt": i + 1, "service": "sshd"}
            }
            alerts = self.ingest_callback(event)
            if alerts:
                all_alerts.extend(alerts)
            events_sent += 1

        return {
            "scenario": "brute_force",
            "title": "Multiple Failed Login Attempts (Brute Force)",
            "events_generated": events_sent,
            "alerts_triggered": len(all_alerts),
            "source_ip": src_ip,
            "target_user": user,
            "status": "COMPLETED"
        }

    # Scenario 2: Successful Login After Multiple Failed Logins
    def _simulate_brute_force_success(self, failed_count: int = 4, src_ip: str = None, user: str = None) -> Dict[str, Any]:
        src_ip = src_ip or "198.51.100.42"
        user = user or "finance_director"
        now = datetime.now(timezone.utc)
        events_sent = 0
        all_alerts = []

        # 1. Series of failed attempts
        for i in range(max(failed_count, 4)):
            ts = (now - timedelta(seconds=(failed_count - i + 1) * 15)).isoformat()
            raw = f"Nov 05 14:10:{10+i} srv-auth02 sshd[9182]: Failed password for {user} from {src_ip} port {51200+i}"
            event = {
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": "10.0.0.10",
                "hostname": "srv-auth02",
                "username": user,
                "event_type": "AUTH_FAILURE",
                "action": "DENY",
                "severity": "MEDIUM",
                "source_system": "auth_server",
                "message": f"Authentication failure for '{user}' from {src_ip}",
                "raw_log": raw,
                "metadata": {"attempt": i + 1}
            }
            alerts = self.ingest_callback(event)
            if alerts:
                all_alerts.extend(alerts)
            events_sent += 1

        # 2. Immediate Successful Login
        ts_success = now.isoformat()
        raw_success = f"Nov 05 14:11:05 srv-auth02 sshd[9190]: Accepted password for {user} from {src_ip} port 51220"
        event_success = {
            "timestamp": ts_success,
            "source_ip": src_ip,
            "destination_ip": "10.0.0.10",
            "hostname": "srv-auth02",
            "username": user,
            "event_type": "AUTH_SUCCESS",
            "action": "LOGIN",
            "severity": "INFO",
            "source_system": "auth_server",
            "message": f"Successful login for user '{user}' from {src_ip} following failed attempts",
            "raw_log": raw_success,
            "metadata": {"attack_stage": "compromise_achieved"}
        }
        alerts = self.ingest_callback(event_success)
        if alerts:
            all_alerts.extend(alerts)
        events_sent += 1

        return {
            "scenario": "brute_force_success",
            "title": "Account Compromise / Successful Login After Failures",
            "events_generated": events_sent,
            "alerts_triggered": len(all_alerts),
            "source_ip": src_ip,
            "target_user": user,
            "status": "COMPLETED"
        }

    # Scenario 3: Repeated Access-Denied Events
    def _simulate_access_denied(self, count: int = 5, src_ip: str = None) -> Dict[str, Any]:
        src_ip = src_ip or "192.168.1.92"
        now = datetime.now(timezone.utc)
        server = "finance-db01"
        forbidden_endpoints = [
            "/api/v1/payroll/salaries",
            "/admin/database/backup.sql",
            "/etc/ssl/private/server.key",
            "/api/v2/internal/tokens",
            "/var/backups/customers.dump"
        ]
        events_sent = 0
        all_alerts = []

        for i in range(min(count, len(forbidden_endpoints))):
            ts = (now - timedelta(seconds=(count - i) * 8)).isoformat()
            uri = forbidden_endpoints[i]
            raw = f'{src_ip} - - [{ts}] "GET {uri} HTTP/1.1" 403 241 "-" "CustomScanner/2.1"'
            event = {
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": "10.0.2.20",
                "hostname": server,
                "username": "guest_probe",
                "event_type": "ACCESS_DENIED",
                "action": "DENY",
                "severity": "HIGH",
                "source_system": "web_server",
                "message": f"HTTP 403 Forbidden: Client {src_ip} denied access to protected URI {uri}",
                "raw_log": raw,
                "metadata": {"endpoint": uri, "http_status": 403}
            }
            alerts = self.ingest_callback(event)
            if alerts:
                all_alerts.extend(alerts)
            events_sent += 1

        return {
            "scenario": "access_denied",
            "title": "Repeated Access-Denied / Directory Traversal Probing",
            "events_generated": events_sent,
            "alerts_triggered": len(all_alerts),
            "source_ip": src_ip,
            "target_host": server,
            "status": "COMPLETED"
        }

    # Scenario 4: Unusual Privileged Account Activity
    def _simulate_privilege_abuse(self, user: str = None) -> Dict[str, Any]:
        user = user or "root"
        now = datetime.now(timezone.utc)
        all_alerts = []

        raw = f"sudo: {user} : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        event = {
            "timestamp": now.isoformat(),
            "source_ip": "10.0.5.88",
            "destination_ip": "10.0.0.5",
            "hostname": "core-vault01",
            "username": user,
            "event_type": "PRIVILEGE_ACTION",
            "action": "EXECUTE",
            "severity": "CRITICAL",
            "source_system": "sudo",
            "message": f"Critical credential access: Account '{user}' executed unauthorized command 'cat /etc/shadow' outside change window",
            "raw_log": raw,
            "metadata": {"command": "/bin/cat /etc/shadow", "risk": "credential_dump"}
        }
        alerts = self.ingest_callback(event)
        if alerts:
            all_alerts.extend(alerts)

        return {
            "scenario": "privilege_abuse",
            "title": "Unusual Privileged Account Activity",
            "events_generated": 1,
            "alerts_triggered": len(all_alerts),
            "target_user": user,
            "status": "COMPLETED"
        }

    # Scenario 5: Sudden Surge in Events
    def _simulate_event_surge(self, count: int = 25, src_ip: str = None) -> Dict[str, Any]:
        src_ip = src_ip or "172.16.8.99"
        now = datetime.now(timezone.utc)
        events_sent = 0
        all_alerts = []

        for i in range(count):
            ts = (now - timedelta(seconds=(count - i) * 1)).isoformat()
            raw = f"<34>Nov 05 14:15:{i%60:02d} edge-fw kernel: [DROP] SRC={src_ip} DST=10.0.0.25 PROTO=UDP SPT=54321 DPT=53"
            event = {
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": "10.0.0.25",
                "hostname": "edge-fw",
                "username": None,
                "event_type": "NETWORK_FLOW",
                "action": "BLOCK",
                "severity": "LOW",
                "source_system": "firewall",
                "message": f"Firewall packet drop for anomalous traffic from {src_ip}",
                "raw_log": raw,
                "metadata": {"packet_index": i + 1}
            }
            alerts = self.ingest_callback(event)
            if alerts:
                all_alerts.extend(alerts)
            events_sent += 1

        return {
            "scenario": "event_surge",
            "title": "Sudden Surge in Security Events",
            "events_generated": events_sent,
            "alerts_triggered": len(all_alerts),
            "source_ip": src_ip,
            "status": "COMPLETED"
        }

    # Scenario 6: Port Scan Reconnaissance
    def _simulate_port_scan(self, src_ip: str = None) -> Dict[str, Any]:
        src_ip = src_ip or "203.0.113.88"
        now = datetime.now(timezone.utc)
        probed_ports = [21, 22, 23, 80, 443, 3306, 3389, 8080]
        events_sent = 0
        all_alerts = []

        for i, port in enumerate(probed_ports):
            ts = (now - timedelta(seconds=(len(probed_ports) - i) * 2)).isoformat()
            event = {
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": "10.0.0.2",
                "hostname": "perimeter-fw01",
                "username": None,
                "event_type": "NETWORK_FLOW",
                "action": "BLOCK",
                "severity": "MEDIUM",
                "source_system": "firewall",
                "message": f"TCP SYN connection to port {port} rejected by firewall rule 104",
                "raw_log": f"DROP TCP {src_ip}:49100 -> 10.0.0.2:{port}",
                "metadata": {"port": port, "protocol": "TCP"}
            }
            alerts = self.ingest_callback(event)
            if alerts:
                all_alerts.extend(alerts)
            events_sent += 1

        return {
            "scenario": "port_scan",
            "title": "Rapid Multi-Port Reconnaissance Probing",
            "events_generated": events_sent,
            "alerts_triggered": len(all_alerts),
            "source_ip": src_ip,
            "status": "COMPLETED"
        }

    # Normal Enterprise Baseline Traffic
    def _simulate_normal_traffic(self, count: int = 15) -> Dict[str, Any]:
        normal_users = ["alice_smith", "bob_johnson", "charlie_lee", "dev_team", "backup_agent"]
        normal_ips = ["192.168.10.15", "192.168.10.22", "192.168.10.45", "192.168.10.89"]
        now = datetime.now(timezone.utc)
        events_sent = 0

        for i in range(count):
            user = random.choice(normal_users)
            ip = random.choice(normal_ips)
            ts = (now - timedelta(seconds=(count - i) * 12)).isoformat()
            
            ev_type = random.choice(["AUTH_SUCCESS", "WEB_REQUEST", "FILE_ACCESS", "SYSTEM_LOG"])
            if ev_type == "AUTH_SUCCESS":
                msg = f"User '{user}' logged in successfully via SSO"
                act = "LOGIN"
                sev = "INFO"
            elif ev_type == "WEB_REQUEST":
                msg = f"GET /dashboard/home HTTP/1.1 status 200 for user '{user}'"
                act = "ALLOW"
                sev = "INFO"
            elif ev_type == "FILE_ACCESS":
                msg = f"User '{user}' opened document /shared/projects/q4_roadmap.pdf"
                act = "READ"
                sev = "INFO"
            else:
                msg = "Routine system health check status OK (cpu=18%, mem=42%)"
                act = "MONITOR"
                sev = "INFO"

            event = {
                "timestamp": ts,
                "source_ip": ip,
                "destination_ip": "10.0.0.100",
                "hostname": "workstation-corp",
                "username": user,
                "event_type": ev_type,
                "action": act,
                "severity": sev,
                "source_system": "corporate_intranet",
                "message": msg,
                "raw_log": f"INFO: {ts} {ip} {user} {msg}",
                "metadata": {"legitimate": True}
            }
            self.ingest_callback(event)
            events_sent += 1

        return {
            "scenario": "normal_traffic",
            "title": "Normal Enterprise Traffic",
            "events_generated": events_sent,
            "alerts_triggered": 0,
            "status": "COMPLETED"
        }

    # Comprehensive Suite: Baseline + All Attack Scenarios
    def _simulate_comprehensive_suite(self) -> Dict[str, Any]:
        summary = {"events_generated": 0, "alerts_triggered": 0, "sub_scenarios": []}
        for fn in [
            self._simulate_normal_traffic,
            self._simulate_brute_force,
            self._simulate_brute_force_success,
            self._simulate_access_denied,
            self._simulate_privilege_abuse,
            self._simulate_event_surge,
            self._simulate_port_scan
        ]:
            res = fn()
            summary["events_generated"] += res["events_generated"]
            summary["alerts_triggered"] += res["alerts_triggered"]
            summary["sub_scenarios"].append(res)
        summary["scenario"] = "comprehensive_suite"
        summary["status"] = "COMPLETED"
        return summary
