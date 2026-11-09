"""
Database module for Centralized Security Log Monitoring and Alert System.
Utilizes SQLite with optimized pragmas and indexes for fast queries.
"""
import sqlite3
import json
import logging
from contextlib import contextmanager
from typing import Generator, Any, Dict, List, Optional
from datetime import datetime, timezone
from app.config import DATABASE_PATH, DEFAULT_RULES

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
-- 1. Security Events Table
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    hostname TEXT,
    username TEXT,
    event_type TEXT NOT NULL,
    action TEXT DEFAULT 'UNKNOWN',
    severity TEXT DEFAULT 'INFO',
    source_system TEXT DEFAULT 'generic',
    message TEXT,
    raw_log TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);

-- 2. Detection Rules Table
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    threshold_count INTEGER NOT NULL,
    enabled INTEGER DEFAULT 1,
    parameters_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 3. Incidents Table (for tracking and workflow)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    assigned_to TEXT DEFAULT 'Unassigned',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolution_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

-- 4. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER,
    rule_code TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'NEW', -- NEW, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, FALSE_POSITIVE
    source_ip TEXT,
    hostname TEXT,
    username TEXT,
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    matched_events_count INTEGER DEFAULT 1,
    incident_id INTEGER,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE SET NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

-- 5. Alert Events Mapping Table
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY(alert_id, event_id),
    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- 6. Incident Notes Table
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
"""

def get_connection() -> sqlite3.Connection:
    """Return a configured SQLite connection."""
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    """Initialize database tables and seed default rules."""
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        now_str = datetime.now(timezone.utc).isoformat()
        
        # Seed rules if not present
        cursor = conn.cursor()
        for r in DEFAULT_RULES:
            cursor.execute("SELECT id FROM rules WHERE rule_code = ?", (r["rule_code"],))
            row = cursor.fetchone()
            if not row:
                cursor.execute(
                    """
                    INSERT INTO rules (rule_code, name, description, severity, window_seconds, threshold_count, enabled, parameters_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r["rule_code"],
                        r["name"],
                        r["description"],
                        r["severity"],
                        r["window_seconds"],
                        r["threshold_count"],
                        r["enabled"],
                        json.dumps(r.get("parameters", {})),
                        now_str,
                        now_str
                    )
                )

def row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    """Convert sqlite3.Row to standard dict."""
    if row is None:
        return None
    return dict(row)

def rows_to_dicts(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    """Convert list of sqlite3.Row to list of dicts."""
    return [dict(r) for r in rows]
