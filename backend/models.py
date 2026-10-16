from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class EventNormalized(BaseModel):
    id: str
    timestamp: str
    category: str # AUTHENTICATION, SYSTEM, NETWORK
    event_type: str # failed_login, successful_login, lateral_connection, privilege_change, data_transfer, etc.
    user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    host: Optional[str] = None
    dest_host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_out: Optional[int] = 0
    action: str = "success"
    severity_score: float = 1.0 # 1.0 to 10.0 for Scatter Plot Y-axis
    status: Optional[str] = "success"
    raw_log: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AlertModel(BaseModel):
    id: str
    title: str
    severity: str # Critical, High, Medium, Low
    risk_score: int # 1 - 100
    rule_id: str
    first_seen: str
    last_seen: str
    primary_user: Optional[str] = None
    primary_ip: Optional[str] = None
    primary_host: Optional[str] = None
    targeted_hosts: List[str] = Field(default_factory=list)
    what_happened: str
    why_correlated: str
    what_remains_uncertain: str
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_tactics: List[Dict[str, str]] = Field(default_factory=list)
    status: str = "New" # New, In Progress, Contained, False Positive, Resolved
    case_id: Optional[str] = None
    created_at: str
    supporting_event_ids: List[str] = Field(default_factory=list)

class CaseCreateRequest(BaseModel):
    title: str
    severity: str = "High"
    assigned_to: str = "SOC Tier 2 Analyst"
    summary: Optional[str] = ""
    alert_ids: List[str] = Field(default_factory=list)

class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    summary: Optional[str] = None

class CaseNoteCreate(BaseModel):
    author: str = "SOC Analyst"
    content: str

class PlaybookSimulateRequest(BaseModel):
    playbook_id: str
    playbook_name: str
    action_name: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    analyst: str = "SOC Analyst"
