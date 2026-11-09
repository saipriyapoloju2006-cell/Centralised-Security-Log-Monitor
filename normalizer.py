"""
Log normalization module.
Parses heterogeneous raw log formats (Syslog, Linux Auth, Apache/Nginx, Windows Events, JSON)
into the Common Information Model (CIM) schema.
"""
import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Regular Expressions for various standard log formats

# Linux auth.log / sshd
RE_SSH_FAILED = re.compile(
    r"(?:Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)|"
    r"authentication failure; logname=.* uid=\d+ euid=\d+ tty=\S* ruser=.* rhost=(\S+)(?:\s+user=(\S+))?)",
    re.IGNORECASE
)
RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
    re.IGNORECASE
)
RE_SUDO_CMD = re.compile(
    r"sudo:\s+(\S+)\s*:\s*TTY=.*COMMAND=(.*)",
    re.IGNORECASE
)

# Apache / Nginx Combined Log: IP - USER [TIMESTAMP] "METHOD URL PROTO" STATUS BYTES "REFERER" "UA"
RE_APACHE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)\s+[^"]*"\s+(\d{3})\s+(\S+)'
)

# Windows Event Log text
RE_WIN_EVENT = re.compile(
    r"EventID:\s*(\d+).*?Account:\s*([^\s,]+).*?SourceIP:\s*([^\s,]+)",
    re.IGNORECASE
)

# Syslog header: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
RE_SYSLOG_RFC3164 = re.compile(
    r"^(?:<(\d+)>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$"
)

def parse_iso_or_now(ts_str: Optional[str]) -> str:
    """Normalize date strings to UTC ISO-8601, or return current UTC time."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        # Check standard ISO format
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        pass
    
    # Check Apache format: 05/Nov/2026:14:22:10 +0000
    try:
        dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        pass

    # Check syslog format: Nov  5 14:22:10
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        pass

    return datetime.now(timezone.utc).isoformat()


def normalize_log_entry(raw_entry: Any) -> Dict[str, Any]:
    """
    Transforms any raw log entry (dict, string, JSON) into standard CIM dictionary.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. If entry is already a dict
    if isinstance(raw_entry, dict):
        return _normalize_dict_entry(raw_entry, now_iso)

    # 2. If entry is a string
    raw_str = str(raw_entry).strip()
    if not raw_str:
        return _create_fallback_entry("", "EMPTY_LOG", now_iso)

    # Try parsing as JSON first
    if (raw_str.startswith("{") and raw_str.endswith("}")) or (raw_str.startswith("[") and raw_str.endswith("]")):
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, dict):
                return _normalize_dict_entry(parsed, now_iso, raw_str)
        except json.JSONDecodeError:
            pass

    # 3. Try Linux Auth Log Patterns
    if "sshd" in raw_str.lower() or "failed password" in raw_str.lower():
        match_fail = RE_SSH_FAILED.search(raw_str)
        if match_fail:
            user = match_fail.group(1) or match_fail.group(5) or "unknown"
            ip = match_fail.group(2) or match_fail.group(4) or "0.0.0.0"
            return {
                "timestamp": now_iso,
                "source_ip": ip,
                "destination_ip": "10.0.0.15",
                "hostname": "auth-server01",
                "username": user,
                "event_type": "AUTH_FAILURE",
                "action": "DENY",
                "severity": "MEDIUM",
                "source_system": "linux_auth",
                "message": f"Failed SSH password attempt for user '{user}' from {ip}",
                "raw_log": raw_str,
                "metadata": {"protocol": "ssh", "service": "sshd"},
                "created_at": now_iso
            }

    if "accepted password" in raw_str.lower() or "accepted publickey" in raw_str.lower():
        match_acc = RE_SSH_ACCEPTED.search(raw_str)
        if match_acc:
            user = match_acc.group(1)
            ip = match_acc.group(2)
            return {
                "timestamp": now_iso,
                "source_ip": ip,
                "destination_ip": "10.0.0.15",
                "hostname": "auth-server01",
                "username": user,
                "event_type": "AUTH_SUCCESS",
                "action": "LOGIN",
                "severity": "INFO",
                "source_system": "linux_auth",
                "message": f"Successful SSH authentication for user '{user}' from {ip}",
                "raw_log": raw_str,
                "metadata": {"protocol": "ssh", "service": "sshd"},
                "created_at": now_iso
            }

    # Sudo / Privilege escalation command
    if "sudo:" in raw_str:
        match_sudo = RE_SUDO_CMD.search(raw_str)
        if match_sudo:
            user = match_sudo.group(1).strip()
            cmd = match_sudo.group(2).strip()
            # Assess severity based on command
            is_sensitive = any(kw in cmd for kw in ["/etc/shadow", "/etc/passwd", "chmod 777", "visudo", "iptables -F", "systemctl stop firewall"])
            return {
                "timestamp": now_iso,
                "source_ip": "127.0.0.1",
                "destination_ip": "127.0.0.1",
                "hostname": "app-server01",
                "username": user,
                "event_type": "PRIVILEGE_ACTION" if is_sensitive else "SYSTEM_EXEC",
                "action": "EXECUTE",
                "severity": "CRITICAL" if is_sensitive else "LOW",
                "source_system": "sudo",
                "message": f"Privileged command executed by '{user}': {cmd}",
                "raw_log": raw_str,
                "metadata": {"command": cmd, "sensitive": is_sensitive},
                "created_at": now_iso
            }

    # 4. Try Apache / Web Server Combined Log
    match_web = RE_APACHE.match(raw_str)
    if match_web:
        ip = match_web.group(1)
        user = match_web.group(2) if match_web.group(2) != "-" else None
        ts = parse_iso_or_now(match_web.group(3))
        method = match_web.group(4)
        uri = match_web.group(5)
        status_code = int(match_web.group(6))

        if status_code in (401, 403):
            ev_type = "ACCESS_DENIED"
            act = "DENY"
            sev = "MEDIUM" if status_code == 403 else "LOW"
        elif status_code >= 500:
            ev_type = "SERVER_ERROR"
            act = "ERROR"
            sev = "LOW"
        else:
            ev_type = "WEB_REQUEST"
            act = "ALLOW"
            sev = "INFO"

        return {
            "timestamp": ts,
            "source_ip": ip,
            "destination_ip": "10.0.0.80",
            "hostname": "web-gateway01",
            "username": user,
            "event_type": ev_type,
            "action": act,
            "severity": sev,
            "source_system": "web_server",
            "message": f"{method} {uri} responded with status {status_code}",
            "raw_log": raw_str,
            "metadata": {"http_method": method, "http_uri": uri, "http_status": status_code},
            "created_at": now_iso
        }

    # 5. Try Windows Event Log Pattern
    match_win = RE_WIN_EVENT.search(raw_str)
    if match_win:
        event_id = match_win.group(1)
        user = match_win.group(2)
        ip = match_win.group(3)

        if event_id == "4625": # Failed logon
            return {
                "timestamp": now_iso,
                "source_ip": ip,
                "destination_ip": "10.0.0.10",
                "hostname": "dc01.corp.local",
                "username": user,
                "event_type": "AUTH_FAILURE",
                "action": "DENY",
                "severity": "MEDIUM",
                "source_system": "windows_security",
                "message": f"Windows Logon Failure (Event ID 4625) for account '{user}' from {ip}",
                "raw_log": raw_str,
                "metadata": {"event_id": 4625},
                "created_at": now_iso
            }
        elif event_id == "4624": # Successful logon
            return {
                "timestamp": now_iso,
                "source_ip": ip,
                "destination_ip": "10.0.0.10",
                "hostname": "dc01.corp.local",
                "username": user,
                "event_type": "AUTH_SUCCESS",
                "action": "LOGIN",
                "severity": "INFO",
                "source_system": "windows_security",
                "message": f"Windows Successful Logon (Event ID 4624) for account '{user}' from {ip}",
                "raw_log": raw_str,
                "metadata": {"event_id": 4624},
                "created_at": now_iso
            }

    # 6. Syslog RFC3164 Fallback
    match_sys = RE_SYSLOG_RFC3164.match(raw_str)
    if match_sys:
        ts_part = match_sys.group(2)
        host = match_sys.group(3)
        tag = match_sys.group(4)
        msg = match_sys.group(5)
        
        # Simple heuristics for syslog message content
        ev_type = "SYSTEM_LOG"
        sev = "INFO"
        act = "LOG"
        if "denied" in msg.lower() or "forbidden" in msg.lower():
            ev_type = "ACCESS_DENIED"
            act = "DENY"
            sev = "HIGH"
        elif "failed" in msg.lower() or "error" in msg.lower():
            ev_type = "SYSTEM_ERROR"
            sev = "MEDIUM"

        return {
            "timestamp": parse_iso_or_now(ts_part),
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "hostname": host,
            "username": None,
            "event_type": ev_type,
            "action": act,
            "severity": sev,
            "source_system": tag,
            "message": msg,
            "raw_log": raw_str,
            "metadata": {"syslog_tag": tag},
            "created_at": now_iso
        }

    # 7. Generic Fallback
    return _create_fallback_entry(raw_str, "RAW_LOG", now_iso)


def _normalize_dict_entry(d: Dict[str, Any], now_iso: str, raw_str: Optional[str] = None) -> Dict[str, Any]:
    """Normalize dictionary input with fallback mapping."""
    ts = parse_iso_or_now(d.get("timestamp"))
    event_type = (d.get("event_type") or d.get("type") or "SYSTEM_EVENT").upper()
    severity = (d.get("severity") or "INFO").upper()
    if severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        severity = "INFO"

    action = (d.get("action") or "UNKNOWN").upper()
    metadata = d.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {"original_metadata": str(metadata)}

    # Extra keys not in core CIM stored in metadata
    core_keys = {"timestamp", "source_ip", "destination_ip", "hostname", "username", "event_type", "action", "severity", "source_system", "message", "raw_log", "metadata"}
    for k, v in d.items():
        if k not in core_keys:
            metadata[k] = v

    return {
        "timestamp": ts,
        "source_ip": d.get("source_ip") or d.get("src_ip") or d.get("ip") or "0.0.0.0",
        "destination_ip": d.get("destination_ip") or d.get("dst_ip") or None,
        "hostname": d.get("hostname") or d.get("host") or d.get("computer_name") or "unknown-host",
        "username": d.get("username") or d.get("user") or None,
        "event_type": event_type,
        "action": action,
        "severity": severity,
        "source_system": d.get("source_system") or d.get("source") or "custom",
        "message": d.get("message") or d.get("msg") or f"Event {event_type} recorded",
        "raw_log": d.get("raw_log") or raw_str or json.dumps(d),
        "metadata": metadata,
        "created_at": now_iso
    }


def _create_fallback_entry(raw_str: str, event_type: str, now_iso: str) -> Dict[str, Any]:
    """Fallback entry for unparsed raw text."""
    return {
        "timestamp": now_iso,
        "source_ip": "0.0.0.0",
        "destination_ip": None,
        "hostname": "system",
        "username": None,
        "event_type": event_type,
        "action": "UNKNOWN",
        "severity": "INFO",
        "source_system": "generic_collector",
        "message": raw_str[:255] if raw_str else "Empty event",
        "raw_log": raw_str,
        "metadata": {"parsed": False},
        "created_at": now_iso
    }


def parse_multiline_logs(content: str) -> List[Dict[str, Any]]:
    """Parse text containing multiple log lines (e.g. from file upload)."""
    normalized_list = []
    lines = content.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        normalized_list.append(normalize_log_entry(line_str))
    return normalized_list
