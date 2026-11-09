"""
Configuration module for Centralized Security Log Monitoring and Alert System.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "security_logs.db"
SAMPLE_LOGS_DIR = DATA_DIR / "sample_logs"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Default Server Settings
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000

# Predefined Detection Rules Specification
DEFAULT_RULES = [
    {
        "rule_code": "RULE-001",
        "name": "Multiple Failed Login Attempts (Brute Force)",
        "description": "Detects repeated failed authentication attempts from a single source IP address within a short timeframe.",
        "severity": "HIGH",
        "window_seconds": 300,
        "threshold_count": 5,
        "enabled": 1,
        "parameters": {
            "target_event": "AUTH_FAILURE",
            "group_by": "source_ip"
        }
    },
    {
        "rule_code": "RULE-002",
        "name": "Successful Login After Multiple Failed Attempts",
        "description": "Detects successful authentication on an account or from an IP immediately preceded by repeated failed attempts (potential credential stuffing or brute-force compromise).",
        "severity": "CRITICAL",
        "window_seconds": 600,
        "threshold_count": 3,
        "enabled": 1,
        "parameters": {
            "trigger_event": "AUTH_SUCCESS",
            "preceded_by": "AUTH_FAILURE",
            "group_by": ["username", "source_ip"]
        }
    },
    {
        "rule_code": "RULE-003",
        "name": "Repeated Access-Denied Events on Server",
        "description": "Detects multiple access-denied or authorization failure events on a single host or resource within a brief window (directory enumeration / privilege probing).",
        "severity": "HIGH",
        "window_seconds": 180,
        "threshold_count": 3,
        "enabled": 1,
        "parameters": {
            "target_event": "ACCESS_DENIED",
            "group_by": ["hostname", "source_ip"]
        }
    },
    {
        "rule_code": "RULE-004",
        "name": "Unusual Privileged Account Activity",
        "description": "Detects sensitive or administrative actions (privilege escalation, shadow file access, firewall disabling, DB export) performed by root or administrator accounts.",
        "severity": "CRITICAL",
        "window_seconds": 60,
        "threshold_count": 1,
        "enabled": 1,
        "parameters": {
            "target_event": "PRIVILEGE_ACTION",
            "privileged_users": ["root", "admin", "administrator", "system", "wheel"]
        }
    },
    {
        "rule_code": "RULE-005",
        "name": "Sudden Surge in Security Events (Volumetric Anomaly)",
        "description": "Detects a sudden high volume of security events originating from a single host or IP, indicating scanning, automated exploitation, or malware beaconing.",
        "severity": "MEDIUM",
        "window_seconds": 60,
        "threshold_count": 20,
        "enabled": 1,
        "parameters": {
            "group_by": "source_ip"
        }
    },
    {
        "rule_code": "RULE-006",
        "name": "Rapid Multi-Port Connection Probing (Port Scan)",
        "description": "Detects connection attempts to 5 or more distinct destination ports from the same source IP in a short duration.",
        "severity": "MEDIUM",
        "window_seconds": 60,
        "threshold_count": 5,
        "enabled": 1,
        "parameters": {
            "target_event": "NETWORK_FLOW",
            "action": "BLOCK",
            "distinct_field": "destination_port"
        }
    }
]
