import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "eventlens.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Events Table (normalized events + preserved raw logs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        host TEXT,
        dest_host TEXT,
        port INTEGER,
        protocol TEXT,
        bytes_out INTEGER DEFAULT 0,
        action TEXT NOT NULL,
        severity_score REAL NOT NULL,
        status TEXT,
        raw_log TEXT NOT NULL,
        metadata_json TEXT
    );
    """)
    
    # 2. Correlated Alerts Table (evidence-first explainable alerts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        rule_id TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        primary_user TEXT,
        primary_ip TEXT,
        primary_host TEXT,
        targeted_hosts_json TEXT,
        what_happened TEXT NOT NULL,
        why_correlated TEXT NOT NULL,
        what_remains_uncertain TEXT NOT NULL,
        recommended_actions_json TEXT NOT NULL,
        mitre_tactics_json TEXT NOT NULL,
        status TEXT DEFAULT 'New',
        case_id TEXT,
        created_at TEXT NOT NULL
    );
    """)
    
    # 3. Alert-Event Association Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_events (
        alert_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        PRIMARY KEY (alert_id, event_id),
        FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
    );
    """)
    
    # 4. Cases Table (Case Management)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Active',
        assigned_to TEXT DEFAULT 'SOC Tier 2 Analyst',
        summary TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    
    # 5. Case Notes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS case_notes (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );
    """)
    
    # 6. Case Audit Logs Table (immutable audit trail)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS case_audit_logs (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        performed_by TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );
    """)
    
    # 7. Playbook Execution Logs (Simulated responses)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS playbook_executions (
        id TEXT PRIMARY KEY,
        playbook_name TEXT NOT NULL,
        action_name TEXT NOT NULL,
        target TEXT NOT NULL,
        parameters_json TEXT,
        simulation_result TEXT NOT NULL,
        performed_by TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL
    );
    """)
    
    conn.commit()
    conn.close()

def clear_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alert_events;")
    cursor.execute("DELETE FROM alerts;")
    cursor.execute("DELETE FROM events;")
    cursor.execute("DELETE FROM case_notes;")
    cursor.execute("DELETE FROM case_audit_logs;")
    cursor.execute("DELETE FROM cases;")
    cursor.execute("DELETE FROM playbook_executions;")
    conn.commit()
    conn.close()

def clear_active_telemetry():
    """Clears the active dataset telemetry (events, alerts, and alert_events)
    while strictly preserving saved cases, case notes, and historical audit logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alert_events;")
    cursor.execute("DELETE FROM alerts;")
    cursor.execute("DELETE FROM events;")
    conn.commit()
    conn.close()

def event_exists(event_id: str = None, timestamp: str = None, user: str = None, source_ip: str = None, event_type: str = None, action: str = None) -> bool:
    """Checks if an event already exists by ID or by matching core telemetry signature."""
    conn = get_db()
    cursor = conn.cursor()
    if event_id:
        row = cursor.execute("SELECT id FROM events WHERE id = ?", (event_id,)).fetchone()
        if row:
            conn.close()
            return True
    if timestamp and event_type and action:
        row = cursor.execute("""
            SELECT id FROM events 
            WHERE timestamp = ? AND event_type = ? AND action = ? 
            AND (user = ? OR (user IS NULL AND ? IS NULL))
            AND (source_ip = ? OR (source_ip IS NULL AND ? IS NULL))
            LIMIT 1
        """, (timestamp, event_type, action, user, user, source_ip, source_ip)).fetchone()
        if row:
            conn.close()
            return True
    conn.close()
    return False

def insert_event(evt: Dict[str, Any]):
    conn = get_db()
    cursor = conn.cursor()
    metadata_str = json.dumps(evt.get("metadata", {}))
    cursor.execute("""
    INSERT OR REPLACE INTO events (
        id, timestamp, category, event_type, user, source_ip, dest_ip, host,
        dest_host, port, protocol, bytes_out, action, severity_score, status,
        raw_log, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evt["id"], evt["timestamp"], evt["category"], evt["event_type"],
        evt.get("user"), evt.get("source_ip"), evt.get("dest_ip"), evt.get("host"),
        evt.get("dest_host"), evt.get("port"), evt.get("protocol"), evt.get("bytes_out", 0),
        evt["action"], evt["severity_score"], evt.get("status", "success"),
        evt["raw_log"], metadata_str
    ))
    conn.commit()
    conn.close()

def insert_alert(alert: Dict[str, Any], event_ids: List[str]):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO alerts (
        id, title, severity, risk_score, rule_id, first_seen, last_seen,
        primary_user, primary_ip, primary_host, targeted_hosts_json,
        what_happened, why_correlated, what_remains_uncertain,
        recommended_actions_json, mitre_tactics_json, status, case_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["id"], alert["title"], alert["severity"], alert["risk_score"], alert["rule_id"],
        alert["first_seen"], alert["last_seen"], alert.get("primary_user"), alert.get("primary_ip"),
        alert.get("primary_host"), json.dumps(alert.get("targeted_hosts", [])),
        alert["what_happened"], alert["why_correlated"], alert["what_remains_uncertain"],
        json.dumps(alert.get("recommended_actions", [])),
        json.dumps(alert.get("mitre_tactics", [])),
        alert.get("status", "New"), alert.get("case_id"), alert["created_at"]
    ))
    
    for eid in event_ids:
        cursor.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", (alert["id"], eid))
        
    conn.commit()
    conn.close()

def get_all_events(limit: int = 1000, category: Optional[str] = None, severity_min: Optional[float] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    
    if category and category != "ALL":
        query += " AND category = ?"
        params.append(category)
    if severity_min is not None:
        query += " AND severity_score >= ?"
        params.append(severity_min)
    if search:
        s = f"%{search}%"
        query += " AND (user LIKE ? OR host LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR event_type LIKE ? OR raw_log LIKE ?)"
        params.extend([s, s, s, s, s, s])
        
    query += " ORDER BY timestamp ASC LIMIT ?"
    params.append(limit)
    
    rows = cursor.execute(query, params).fetchall()
    events = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        events.append(d)
    conn.close()
    return events

def get_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    row = cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
    return d

def get_all_alerts() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    alerts = []
    for r in rows:
        d = dict(r)
        d["targeted_hosts"] = json.loads(d.pop("targeted_hosts_json") or "[]")
        d["recommended_actions"] = json.loads(d.pop("recommended_actions_json") or "[]")
        d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json") or "[]")
        # fetch supporting event IDs
        ev_rows = cursor.execute("SELECT event_id FROM alert_events WHERE alert_id = ?", (d["id"],)).fetchall()
        d["supporting_event_ids"] = [e["event_id"] for e in ev_rows]
        alerts.append(d)
    conn.close()
    return alerts

def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    row = cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        conn.close()
        return None
    d = dict(row)
    d["targeted_hosts"] = json.loads(d.pop("targeted_hosts_json") or "[]")
    d["recommended_actions"] = json.loads(d.pop("recommended_actions_json") or "[]")
    d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json") or "[]")
    
    # fetch supporting events fully
    ev_rows = cursor.execute("""
    SELECT e.* FROM events e
    JOIN alert_events ae ON e.id = ae.event_id
    WHERE ae.alert_id = ?
    ORDER BY e.timestamp ASC
    """, (alert_id,)).fetchall()
    
    supporting_events = []
    for ev in ev_rows:
        ed = dict(ev)
        ed["metadata"] = json.loads(ed.pop("metadata_json") or "{}")
        supporting_events.append(ed)
        
    d["supporting_events"] = supporting_events
    d["supporting_event_ids"] = [e["id"] for e in supporting_events]
    conn.close()
    return d
