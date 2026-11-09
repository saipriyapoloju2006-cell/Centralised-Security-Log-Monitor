"""
Pydantic data models for validation and schema definition.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class LogEntryInput(BaseModel):
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    event_type: str = Field(..., description="e.g. AUTH_FAILURE, AUTH_SUCCESS, ACCESS_DENIED, PRIVILEGE_ACTION, NETWORK_FLOW")
    action: Optional[str] = "UNKNOWN" # ALLOW, BLOCK, DENY, LOGIN, LOGOUT, EXECUTE
    severity: Optional[str] = "INFO" # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source_system: Optional[str] = "generic" # firewall, auth_server, web_server, workstation, db
    message: Optional[str] = None
    raw_log: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class RawLogUpload(BaseModel):
    raw_text: str
    format: Optional[str] = "auto" # auto, syslog, apache, auth_log, json

class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    window_seconds: Optional[int] = None
    threshold_count: Optional[int] = None
    severity: Optional[str] = None

class AlertStatusUpdate(BaseModel):
    status: str # NEW, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, FALSE_POSITIVE
    incident_id: Optional[int] = None

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "HIGH"
    assigned_to: Optional[str] = "Security Analyst"
    alert_ids: Optional[List[int]] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

class IncidentNoteCreate(BaseModel):
    author: str = "Analyst"
    note: str

class SimulationScenarioRequest(BaseModel):
    scenario: str # brute_force, brute_force_success, access_denied, privilege_abuse, event_surge, port_scan, normal_traffic
    intensity: Optional[int] = 5
    target_ip: Optional[str] = None
    target_user: Optional[str] = None
