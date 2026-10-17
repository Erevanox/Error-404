import os
import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from database import (
    init_db, clear_db, clear_active_telemetry, event_exists, insert_event, insert_alert, get_all_events,
    get_event_by_id, get_all_alerts, get_alert_by_id, get_db
)
from normalizer import normalize_json_payload, normalize_csv_payload
from detector import run_correlation_engine
from sample_data import get_canonical_scenario, save_sample_datasets
from exporter import generate_pdf_report, generate_csv_export
from models import (
    CaseCreateRequest, CaseUpdateRequest, CaseNoteCreate, PlaybookSimulateRequest
)

app = FastAPI(
    title="TraceX SOC Backend",
    description="Cybersecurity Incident Correlation & Visualization System",
    version="2.4.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()
    clear_db()
    save_sample_datasets()
    # Initial state is strictly clean and empty (0 records, 0 alerts).
    # Demo data is loaded ONLY when the user explicitly triggers 'Load Demo Data'.

def load_canonical_data():
    clear_db()
    canonical_events = get_canonical_scenario()
    for ev in canonical_events:
        insert_event(ev)
    # Run correlation engine
    alerts = run_correlation_engine(canonical_events)
    for alert, event_ids in alerts:
        insert_alert(alert, event_ids)
        
    # Auto-create initial investigation case for the critical incident
    if alerts:
        critical_alert = alerts[0][0]
        case_id = f"CASE-2026-{uuid.uuid4().hex[:4].upper()}"
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat() + "Z"
        cursor.execute("""
        INSERT INTO cases (id, title, severity, status, assigned_to, summary, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            f"Investigation: {critical_alert['title']}",
            critical_alert['severity'],
            "In Progress",
            "SOC Tier 2 Analyst",
            "Automatic case opened from high-confidence correlation alert. Immediate review requested.",
            now, now
        ))
        
        # Link alert to case
        cursor.execute("UPDATE alerts SET case_id = ? WHERE id = ?", (case_id, critical_alert["id"]))
        
        # Add initial note
        cursor.execute("""
        INSERT INTO case_notes (id, case_id, author, content, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (
            f"note-{uuid.uuid4().hex[:6]}",
            case_id,
            "SOC Tier 2 Lead",
            "Triage initiated: Correlated 5 authentication failures followed by successful session and lateral jumps to internal servers.",
            now
        ))
        
        # Add audit log
        cursor.execute("""
        INSERT INTO case_audit_logs (id, case_id, action, details, performed_by, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            f"audit-{uuid.uuid4().hex[:6]}",
            case_id,
            "CASE_CREATED",
            f"Case auto-created from correlated alert {critical_alert['id']}",
            "Correlation Engine v2.4",
            now
        ))
        conn.commit()
        conn.close()

# -----------------------------------------------------------------------------
# Core Status & Stats Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TraceX Incident Correlation Engine",
        "mode": "Defensive Synthetic SOC Sandbox",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

@app.get("/api/stats")
def get_stats():
    events = get_all_events(limit=5000)
    alerts = get_all_alerts()
    
    total_events = len(events)
    detection_alerts = len([e for e in events if e.get("severity_score", 1.0) >= 4.0 or e.get("status") == "failure"])
    correlated_alerts = len(alerts)
    validation_errors = 0
    
    alerts_requiring_review = len([a for a in alerts if a.get("status") in ("New", "Active", "In Progress")])
    high_concern_patterns = len([a for a in alerts if a.get("severity") in ("Critical", "High")])
    normal_events = len([e for e in events if e.get("severity_score", 1.0) < 4.0])
    
    category_counts = {"AUTHENTICATION": 0, "SYSTEM": 0, "NETWORK": 0}
    severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    for e in events:
        cat = e.get("category", "SYSTEM")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        
    for a in alerts:
        sev = a.get("severity", "Low")
        severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
        
    return {
        "total_events": total_events,
        "total_records": total_events,
        "detection_alerts": detection_alerts,
        "correlated_alerts": correlated_alerts,
        "validation_errors": validation_errors,
        "alerts_requiring_review": alerts_requiring_review,
        "high_concern_patterns": high_concern_patterns,
        "normal_events": normal_events,
        "category_counts": category_counts,
        "severity_distribution": severity_distribution,
        "total_alerts": len(alerts)
    }

# -----------------------------------------------------------------------------
# Events Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/events")
def list_events(
    category: Optional[str] = Query(None),
    severity_min: Optional[float] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(500)
):
    events = get_all_events(limit=limit, category=category, severity_min=severity_min, search=search)
    return {
        "count": len(events),
        "events": events
    }

@app.get("/api/events/scatter")
def get_scatter_events(
    category: Optional[str] = Query(None),
    severity_min: Optional[float] = Query(None),
    search: Optional[str] = Query(None)
):
    events = get_all_events(limit=2000, category=category, severity_min=severity_min, search=search)
    scatter_points = []
    for e in events:
        scatter_points.append({
            "id": e["id"],
            "timestamp": e["timestamp"],
            "time_display": e["timestamp"][11:19],
            "severity_score": e["severity_score"],
            "category": e["category"],
            "event_type": e["event_type"],
            "user": e.get("user") or "N/A",
            "host": e.get("host") or "N/A",
            "dest_host": e.get("dest_host") or e.get("dest_ip") or "N/A",
            "action": e.get("action", "unknown"),
            "status": e.get("status", "unknown")
        })
    return scatter_points

@app.get("/api/events/{event_id}")
def get_event_detail(event_id: str):
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

# -----------------------------------------------------------------------------
# Alerts & Traceback Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/alerts")
def list_alerts():
    alerts = get_all_alerts()
    return {
        "count": len(alerts),
        "alerts": alerts
    }

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # Generate React Flow nodes and edges for the Traceback Graph
    traceback = build_traceback_graph(alert)
    alert["traceback_graph"] = traceback
    return alert

def build_traceback_graph(alert: Dict[str, Any]) -> Dict[str, Any]:
    nodes = []
    edges = []
    
    primary_ip = alert.get("primary_ip") or "192.168.1.105"
    primary_user = alert.get("primary_user") or "m.vasquez"
    primary_host = alert.get("primary_host") or "WORKSTATION-04"
    targeted_hosts = alert.get("targeted_hosts") or ["FILE-SRV02", "PROD-DB01"]
    
    # 1. Source IP Node
    nodes.append({
        "id": "node-source-ip",
        "type": "socNode",
        "data": {
            "label": f"Origin IP: {primary_ip}",
            "nodeType": "source_ip",
            "icon": "Network",
            "badge": "Threat Origin",
            "details": f"External/Internal origin address ({primary_ip})"
        },
        "position": {"x": 50, "y": 180}
    })
    
    # 2. User Account Node
    nodes.append({
        "id": "node-user",
        "type": "socNode",
        "data": {
            "label": f"User: {primary_user}",
            "nodeType": "user",
            "icon": "User",
            "badge": "Target Credential",
            "details": f"Account identity targeted across 5 failed attempts"
        },
        "position": {"x": 280, "y": 180}
    })
    
    edges.append({
        "id": "edge-ip-user",
        "source": "node-source-ip",
        "target": "node-user",
        "label": "5x Auth Failures -> SSH/PAM Accepted",
        "animated": True,
        "style": {"stroke": "#ef4444", "strokeWidth": 2}
    })
    
    # 3. Workstation/Origin Host Node
    nodes.append({
        "id": "node-origin-host",
        "type": "socNode",
        "data": {
            "label": f"Host: {primary_host}",
            "nodeType": "host",
            "icon": "Server",
            "badge": "Compromised Asset",
            "details": f"Initial foothold endpoint ({primary_host})"
        },
        "position": {"x": 520, "y": 180}
    })
    
    edges.append({
        "id": "edge-user-host",
        "source": "node-user",
        "target": "node-origin-host",
        "label": "Session Established",
        "animated": True,
        "style": {"stroke": "#3b82f6", "strokeWidth": 2}
    })
    
    # 4. Destination Systems (Lateral Movement)
    y_offset = 60
    for idx, target in enumerate(targeted_hosts):
        tid = f"node-target-{idx}"
        is_external = "EXTERNAL" in target or "203." in target or "198." in target
        node_badge = "Exfiltration Target" if is_external else "Lateral Hop"
        edge_label = "Egress Spike (84MB)" if is_external else "SMB / SSH Port 445/22"
        edge_color = "#f97316" if is_external else "#8b5cf6"
        
        nodes.append({
            "id": tid,
            "type": "socNode",
            "data": {
                "label": f"Target: {target}",
                "nodeType": "dest_host" if not is_external else "external_c2",
                "icon": "HardDrive" if not is_external else "Globe",
                "badge": node_badge,
                "details": f"Internal infrastructure destination: {target}"
            },
            "position": {"x": 780, "y": y_offset}
        })
        
        edges.append({
            "id": f"edge-host-target-{idx}",
            "source": "node-origin-host",
            "target": tid,
            "label": edge_label,
            "animated": True,
            "style": {"stroke": edge_color, "strokeWidth": 2}
        })
        y_offset += 140
        
    return {"nodes": nodes, "edges": edges}

# -----------------------------------------------------------------------------
# Log Upload & Sample Data Endpoints
# -----------------------------------------------------------------------------
@app.post("/api/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    mode: str = Form("append"),
    date_format: str = Form("auto"),
    time_format: str = Form("auto")
):
    filename = file.filename or "uploaded_file"
    content_bytes = await file.read()
    
    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_text = content_bytes.decode("latin-1")
        
    events = []
    errors = []
    
    if filename.endswith(".csv"):
        events, errors = normalize_csv_payload(content_text, date_format=date_format, time_format=time_format)
    elif filename.endswith(".json"):
        events, errors = normalize_json_payload(content_text, date_format=date_format, time_format=time_format)
    else:
        # Try JSON first, then CSV
        events, errors = normalize_json_payload(content_text, date_format=date_format, time_format=time_format)
        if not events:
            events, csv_err = normalize_csv_payload(content_text, date_format=date_format, time_format=time_format)
            if not events:
                errors.extend(csv_err)
                
    if not events:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Failed to parse logs from uploaded file.",
                "errors": errors or ["No valid event entries discovered."]
            }
        )
        
    upload_mode = mode.lower().strip()
    duplicates_skipped = 0
    new_events_inserted = 0

    if upload_mode in ("clear", "replace"):
        # Task 3/4: Clear & Load New: cleanly reset active telemetry while preserving saved cases
        clear_active_telemetry()
        for ev in events:
            insert_event(ev)
        new_events_inserted = len(events)
    else:
        # Task 3/4: Add to Existing Data: preserve existing records, apply deduplication policy
        new_events = []
        for ev in events:
            if event_exists(
                event_id=ev.get("id"),
                timestamp=ev.get("timestamp"),
                user=ev.get("user"),
                source_ip=ev.get("source_ip"),
                event_type=ev.get("event_type"),
                action=ev.get("action")
            ):
                duplicates_skipped += 1
            else:
                new_events.append(ev)
                
        for ev in new_events:
            insert_event(ev)
        new_events_inserted = len(new_events)
        
    # Run correlation engine on all current events
    all_events = get_all_events(limit=5000)
    alerts = run_correlation_engine(all_events)
    for alert, event_ids in alerts:
        insert_alert(alert, event_ids)
        
    return {
        "success": True,
        "filename": filename,
        "mode": upload_mode,
        "parsed_events_count": len(events),
        "new_events_inserted": new_events_inserted,
        "duplicates_skipped": duplicates_skipped,
        "total_database_events": len(all_events),
        "new_alerts_generated": len(alerts),
        "errors": errors
    }

@app.post("/api/reset-demo")
def reset_demo():
    load_canonical_data()
    return {
        "success": True,
        "message": "Demo reset successfully to canonical brute force and lateral movement scenario."
    }

@app.post("/api/load-sample/{scenario_name}")
def load_sample_scenario(scenario_name: str):
    if scenario_name == "canonical":
        load_canonical_data()
        return {"success": True, "message": "Loaded Canonical Attack Scenario (Brute force + Lateral movement)."}
    elif scenario_name == "exfil":
        clear_db()
        exfil_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "datasets", "sample_data_exfiltration.json")
        with open(exfil_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        for ev in events:
            insert_event(ev)
        alerts = run_correlation_engine(events)
        for alert, event_ids in alerts:
            insert_alert(alert, event_ids)
        return {"success": True, "message": "Loaded High-Volume Egress / Data Exfiltration scenario."}
    else:
        load_canonical_data()
        return {"success": True, "message": "Defaulted to Canonical scenario."}

@app.post("/api/clear")
def clear_telemetry():
    clear_active_telemetry()
    return {"success": True, "message": "Active telemetry cleared successfully."}

# -----------------------------------------------------------------------------
# Case Management & Audit Trail Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/cases")
def list_cases():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    cases = []
    for r in rows:
        d = dict(r)
        # count notes
        notes_count = cursor.execute("SELECT COUNT(*) as cnt FROM case_notes WHERE case_id = ?", (d["id"],)).fetchone()["cnt"]
        d["notes_count"] = notes_count
        cases.append(d)
    conn.close()
    return {"cases": cases}

@app.post("/api/cases")
def create_case(req: CaseCreateRequest):
    case_id = f"CASE-2026-{uuid.uuid4().hex[:4].upper()}"
    now = datetime.now(timezone.utc).isoformat() + "Z"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO cases (id, title, severity, status, assigned_to, summary, created_at, updated_at)
    VALUES (?, ?, ?, 'Active', ?, ?, ?, ?)
    """, (case_id, req.title, req.severity, req.assigned_to, req.summary or "", now, now))
    
    # Link alerts
    for aid in req.alert_ids:
        cursor.execute("UPDATE alerts SET case_id = ? WHERE id = ?", (case_id, aid))
        
    # Audit log
    cursor.execute("""
    INSERT INTO case_audit_logs (id, case_id, action, details, performed_by, timestamp)
    VALUES (?, ?, 'CASE_CREATED', ?, ?, ?)
    """, (f"audit-{uuid.uuid4().hex[:6]}", case_id, f"Case manually opened with {len(req.alert_ids)} linked alerts", req.assigned_to, now))
    
    conn.commit()
    conn.close()
    return {"success": True, "case_id": case_id}

@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: str):
    conn = get_db()
    cursor = conn.cursor()
    case_row = cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Case not found")
        
    case_data = dict(case_row)
    
    # fetch linked alerts
    alerts_rows = cursor.execute("SELECT id, title, severity, risk_score FROM alerts WHERE case_id = ?", (case_id,)).fetchall()
    case_data["linked_alerts"] = [dict(a) for a in alerts_rows]
    
    # fetch notes
    notes_rows = cursor.execute("SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()
    case_data["notes"] = [dict(n) for n in notes_rows]
    
    # fetch audit logs
    audit_rows = cursor.execute("SELECT * FROM case_audit_logs WHERE case_id = ? ORDER BY timestamp DESC", (case_id,)).fetchall()
    case_data["audit_logs"] = [dict(au) for au in audit_rows]
    
    conn.close()
    return case_data

@app.put("/api/cases/{case_id}")
def update_case(case_id: str, req: CaseUpdateRequest):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat() + "Z"
    
    if req.status:
        cursor.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?", (req.status, now, case_id))
        cursor.execute("""
        INSERT INTO case_audit_logs (id, case_id, action, details, performed_by, timestamp)
        VALUES (?, ?, 'STATUS_CHANGED', ?, 'Analyst', ?)
        """, (f"audit-{uuid.uuid4().hex[:6]}", case_id, f"Status updated to '{req.status}'", now))
        
    if req.assigned_to:
        cursor.execute("UPDATE cases SET assigned_to = ?, updated_at = ? WHERE id = ?", (req.assigned_to, now, case_id))
    if req.summary is not None:
        cursor.execute("UPDATE cases SET summary = ?, updated_at = ? WHERE id = ?", (req.summary, now, case_id))
        
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/cases/{case_id}/notes")
def add_case_note(case_id: str, req: CaseNoteCreate):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat() + "Z"
    note_id = f"note-{uuid.uuid4().hex[:6]}"
    
    cursor.execute("""
    INSERT INTO case_notes (id, case_id, author, content, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (note_id, case_id, req.author, req.content, now))
    
    cursor.execute("""
    INSERT INTO case_audit_logs (id, case_id, action, details, performed_by, timestamp)
    VALUES (?, ?, 'NOTE_ADDED', ?, ?, ?)
    """, (f"audit-{uuid.uuid4().hex[:6]}", case_id, f"Analyst note added: {req.content[:40]}...", req.author, now))
    
    conn.commit()
    conn.close()
    return {"success": True, "note_id": note_id}

# -----------------------------------------------------------------------------
# Response Playbooks (Simulated Actions Only)
# -----------------------------------------------------------------------------
@app.post("/api/playbooks/simulate")
def simulate_playbook_action(req: PlaybookSimulateRequest):
    exec_id = f"sim-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat() + "Z"
    
    sim_messages = {
        "revoke_tokens": f"[SIMULATION] Session revocation payload dispatched to IdP/Okta API for target user '{req.target}'. Active JWT tokens invalidated. No live disruption occurred.",
        "quarantine_host": f"[SIMULATION] Network isolation request transmitted to simulated EDR agent on '{req.target}'. Host inbound/outbound packets redirected to containment VLAN.",
        "force_password_reset": f"[SIMULATION] Active Directory flag 'UserMustChangePasswordAtNextLogon' set for '{req.target}'. Outbound notification simulated.",
        "block_ip": f"[SIMULATION] Perimeter firewall null-route rule staged for origin IP '{req.target}' on port 443. Traffic drop rule logged in mock ACL table.",
        "snapshot_memory": f"[SIMULATION] Volatile memory snapshot command dispatched to endpoint '{req.target}'. Dump artifact preserved in simulated forensic sandbox."
    }
    
    result_text = sim_messages.get(
        req.action_name,
        f"[SIMULATION] Defensive playbook action '{req.action_name}' staged and executed safely against mock target '{req.target}'. No real infrastructure modified."
    )
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO playbook_executions (id, playbook_name, action_name, target, parameters_json, simulation_result, performed_by, timestamp, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SUCCESS')
    """, (
        exec_id, req.playbook_name, req.action_name, req.target,
        json.dumps(req.parameters), result_text, req.analyst, now
    ))
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "execution_id": exec_id,
        "action": req.action_name,
        "target": req.target,
        "simulation_result": result_text,
        "timestamp": now,
        "ethical_notice": "SIMULATION ONLY: No destructive or unapproved network changes were committed."
    }

@app.get("/api/playbooks/history")
def get_playbook_history():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM playbook_executions ORDER BY timestamp DESC LIMIT 50").fetchall()
    history = [dict(r) for r in rows]
    conn.close()
    return {"history": history}

# -----------------------------------------------------------------------------
# Reports & Exports Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/reports/pdf")
def export_general_pdf_report():
    events = get_all_events(limit=5000)
    alerts = get_all_alerts()
    cases_resp = list_cases()
    first_case = cases_resp["cases"][0] if cases_resp.get("cases") else None
    first_alert = alerts[0] if alerts else None
    notes = []
    if first_case:
        conn = get_db()
        cursor = conn.cursor()
        notes = [dict(n) for n in cursor.execute("SELECT * FROM case_notes WHERE case_id = ?", (first_case["id"],)).fetchall()]
        conn.close()
        
    pdf_bytes = generate_pdf_report(
        alert=first_alert,
        case=first_case,
        notes=notes,
        all_events=events,
        all_alerts=alerts,
        stats=get_stats()
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="TraceX_Cybersecurity_Investigation_Report.pdf"'}
    )

@app.get("/api/reports/pdf/{alert_id}")
def export_pdf_report(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    case = None
    notes = []
    if alert.get("case_id"):
        conn = get_db()
        cursor = conn.cursor()
        c_row = cursor.execute("SELECT * FROM cases WHERE id = ?", (alert["case_id"],)).fetchone()
        if c_row:
            case = dict(c_row)
            n_rows = cursor.execute("SELECT * FROM case_notes WHERE case_id = ?", (alert["case_id"],)).fetchall()
            notes = [dict(n) for n in n_rows]
        conn.close()
        
    all_events = get_all_events(limit=5000)
    all_alerts = get_all_alerts()
    pdf_bytes = generate_pdf_report(
        alert=alert,
        case=case,
        notes=notes,
        all_events=all_events,
        all_alerts=all_alerts,
        stats=get_stats()
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="TraceX_Report_{alert_id}.pdf"'}
    )

@app.get("/api/reports/csv")
def export_csv_evidence():
    events = get_all_events(limit=5000)
    csv_content = generate_csv_export(events)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="TraceX_Evidence_Export.csv"'}
    )
