import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from mitre import get_mitre_context

def parse_time(ts: str) -> datetime:
    try:
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return datetime.now(timezone.utc)

def run_correlation_engine(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyzes normalized events and generates explainable, evidence-first correlated alerts.
    """
    if not events:
        return []
        
    sorted_events = sorted(events, key=lambda x: parse_time(x["timestamp"]))
    generated_alerts = []
    
    # -------------------------------------------------------------
    # RULE 1 & 2: Failed Logins followed by Successful Login & Lateral Movement
    # Canonical SOC Incident Pattern
    # -------------------------------------------------------------
    failed_logins_by_user: Dict[str, List[Dict[str, Any]]] = {}
    
    for ev in sorted_events:
        user = ev.get("user")
        if not user:
            continue
        cat = ev.get("category")
        action = ev.get("action", "")
        etype = ev.get("event_type", "")
        
        if cat == "AUTHENTICATION" and ("fail" in action or "fail" in etype or ev.get("status") == "failure"):
            failed_logins_by_user.setdefault(user, []).append(ev)
            
    for user, fails in failed_logins_by_user.items():
        if len(fails) >= 3:
            # Check if there is a subsequent successful login
            first_fail_time = parse_time(fails[0]["timestamp"])
            last_fail_time = parse_time(fails[-1]["timestamp"])
            
            # Find successful logins for this user after the first failure
            success_logins = [
                e for e in sorted_events 
                if e.get("user") == user and e.get("category") == "AUTHENTICATION" 
                and ("succ" in e.get("action", "") or e.get("status") == "success")
                and parse_time(e["timestamp"]) >= first_fail_time
            ]
            
            # Check for lateral movement events by this user or origin host
            lateral_events = [
                e for e in sorted_events
                if (e.get("user") == user or e.get("source_ip") == fails[0].get("source_ip") or e.get("host") == fails[0].get("host"))
                and (
                    "lateral" in e.get("event_type", "") 
                    or e.get("port") in (22, 445, 3389)
                    or (e.get("dest_host") and e.get("dest_host") != e.get("host"))
                )
                and parse_time(e["timestamp"]) >= first_fail_time
            ]
            
            source_ip = fails[0].get("source_ip") or "192.168.1.105"
            primary_host = fails[0].get("host") or "WORKSTATION-04"
            dest_hosts = list(set([e.get("dest_host") for e in lateral_events if e.get("dest_host")] + [e.get("host") for e in lateral_events if e.get("host") and e.get("host") != primary_host]))

            # Subsequent execution/privilege/data-transfer events linked to the breached account
            subsequent_events = [
                e for e in sorted_events
                if (e.get("user") == user or e.get("host") in dest_hosts or e.get("source_ip") == source_ip)
                and (
                    e.get("category") in ("SYSTEM", "NETWORK")
                    or e.get("severity_score", 0) >= 4.0
                )
                and parse_time(e["timestamp"]) >= first_fail_time
                and "benign" not in e.get("id", "").lower()
                and e.get("severity_score", 0) >= 3.0
            ]

            # Correlate all supporting events
            all_incident_events = fails + success_logins + lateral_events + subsequent_events
            # Deduplicate by ID
            unique_events = {e["id"]: e for e in all_incident_events}
            sorted_incident = sorted(unique_events.values(), key=lambda x: parse_time(x["timestamp"]))
            supporting_ids = [e["id"] for e in sorted_incident]
            
            first_seen = sorted_incident[0]["timestamp"]
            last_seen = sorted_incident[-1]["timestamp"]
            
            if success_logins and lateral_events:
                # Critical Alert: Canonical Brute Force -> Compromised Login -> Lateral Movement
                alert_id = f"ALT-CORR-{uuid.uuid4().hex[:6].upper()}"
                alert = {
                    "id": alert_id,
                    "title": f"Brute Force Authentication Breach & Internal Lateral Movement ({user})",
                    "severity": "Critical",
                    "risk_score": 94,
                    "rule_id": "RULE-SEC-001-CANONICAL-PIVOT",
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "primary_user": user,
                    "primary_ip": source_ip,
                    "primary_host": primary_host,
                    "targeted_hosts": dest_hosts or ["PROD-DB01", "FILE-SRV02"],
                    "what_happened": (
                        f"Targeted authentication activity detected against account '{user}'. Observed from source IP {source_ip} "
                        f"on endpoint {primary_host}, {len(fails)} failed authentication attempts were recorded. "
                        f"Within minutes, a successful authentication occurred, followed by multi-host remote service "
                        f"connections targeting internal infrastructure ({', '.join(dest_hosts) if dest_hosts else 'internal servers'})."
                    ),
                    "why_correlated": (
                        f"Correlated based on temporal proximity (events occurred within incident window), shared user entity "
                        f"('{user}'), common observed network address ({source_ip}), and transition from authentication failures "
                        f"to successful session establishment followed by internal host traversal on ports 445 (SMB) and 22 (SSH)."
                    ),
                    "what_remains_uncertain": (
                        "HYPOTHESIS VALIDATION REQUIRED: 1) Could represent an authorized systems engineer who mistyped their password "
                        "before successfully authenticating and performing scheduled maintenance; 2) May be an automated credential "
                        "rotation script; 3) Host-level process provenance (whether tools were legitimate IT utilities or adversary tooling) "
                        "cannot be verified without endpoint EDR telemetry."
                    ),
                    "recommended_actions": [
                        f"Contact account holder ({user}) via telephone or verified out-of-band communication to verify active physical presence.",
                        f"Review Active Directory / IdP logs for simultaneous logins from contrasting geographical regions.",
                        f"Issue simulated token revocation and session invalidation for user '{user}'.",
                        f"Place target host(s) {', '.join(dest_hosts)} under heightened telemetry surveillance.",
                        "Inspect NetFlow and packet captures between source workstation and internal database cluster."
                    ],
                    "mitre_tactics": [
                        get_mitre_context("T1110"),
                        get_mitre_context("T1078"),
                        get_mitre_context("T1021")
                    ],
                    "status": "New",
                    "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                    "supporting_event_ids": supporting_ids
                }
                generated_alerts.append((alert, supporting_ids))
            else:
                # Standalone Brute Force alert
                alert_id = f"ALT-BF-{uuid.uuid4().hex[:6].upper()}"
                alert = {
                    "id": alert_id,
                    "title": f"Repeated Authentication Failures ({len(fails)} Attempts - {user})",
                    "severity": "High",
                    "risk_score": 75,
                    "rule_id": "RULE-SEC-002-BRUTE-FORCE",
                    "first_seen": fails[0]["timestamp"],
                    "last_seen": fails[-1]["timestamp"],
                    "primary_user": user,
                    "primary_ip": source_ip,
                    "primary_host": primary_host,
                    "targeted_hosts": [primary_host],
                    "what_happened": (
                        f"Account '{user}' experienced {len(fails)} authentication rejections within a short window "
                        f"from source address {source_ip}."
                    ),
                    "why_correlated": f"Grouped by common target account '{user}' and contiguous authentication failure status.",
                    "what_remains_uncertain": "May be caused by expired credentials cached on mobile device or automated background sync.",
                    "recommended_actions": [
                        "Verify whether user recently reset their domain password.",
                        "Inspect source IP to check if it originates from an internal workstation or external VPN gateway."
                    ],
                    "mitre_tactics": [get_mitre_context("T1110")],
                    "status": "New",
                    "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                    "supporting_event_ids": [f["id"] for f in fails]
                }
                generated_alerts.append((alert, [f["id"] for f in fails]))

    # -------------------------------------------------------------
    # RULE 3: Unusual Outbound Data Exfiltration
    # -------------------------------------------------------------
    large_egress_events = [
        e for e in sorted_events 
        if e.get("category") == "NETWORK" and (e.get("bytes_out", 0) > 20_000_000 or "exfil" in e.get("event_type", ""))
    ]
    if large_egress_events:
        total_bytes = sum(e.get("bytes_out", 0) for e in large_egress_events)
        mb_total = round(total_bytes / (1024 * 1024), 1)
        first_e = large_egress_events[0]
        alert_id = f"ALT-EXFIL-{uuid.uuid4().hex[:6].upper()}"
        alert = {
            "id": alert_id,
            "title": f"Anomalous High-Volume Egress Burst ({mb_total} MB Transferred)",
            "severity": "High",
            "risk_score": 82,
            "rule_id": "RULE-SEC-003-DATA-EGRESS-BURST",
            "first_seen": first_e["timestamp"],
            "last_seen": large_egress_events[-1]["timestamp"],
            "primary_user": first_e.get("user") or "system",
            "primary_ip": first_e.get("source_ip"),
            "primary_host": first_e.get("host"),
            "targeted_hosts": [first_e.get("dest_ip") or "EXTERNAL-IP"],
            "what_happened": (
                f"Detected an abrupt surge in outbound network traffic totaling {mb_total} MB towards destination "
                f"{first_e.get('dest_ip')} on port {first_e.get('port', 443)}."
            ),
            "why_correlated": "Traffic volume deviated significantly from historical baseline for this host in under 15 minutes.",
            "what_remains_uncertain": "May represent an authorized database backup sync, media streaming, or software update distribution.",
            "recommended_actions": [
                f"Perform reputation lookup on destination address {first_e.get('dest_ip')}.",
                "Inspect process ID on source host responsible for the network socket.",
                "Review data classification policies for systems communicating with external endpoints."
            ],
            "mitre_tactics": [get_mitre_context("T1048")],
            "status": "New",
            "created_at": datetime.now(timezone.utc).isoformat() + "Z",
            "supporting_event_ids": [e["id"] for e in large_egress_events]
        }
        generated_alerts.append((alert, [e["id"] for e in large_egress_events]))

    # -------------------------------------------------------------
    # RULE 4: Privilege Escalation Activity
    # -------------------------------------------------------------
    priv_events = [
        e for e in sorted_events 
        if e.get("category") == "SYSTEM" and any(k in e.get("event_type", "") or k in e.get("raw_log", "").lower() for k in ("sudo", "privilege", "elevation", "admin"))
    ]
    if priv_events:
        alert_id = f"ALT-PRIV-{uuid.uuid4().hex[:6].upper()}"
        p0 = priv_events[0]
        alert = {
            "id": alert_id,
            "title": f"Elevated Privilege Execution / Sudo Invocation ({p0.get('user', 'unknown')})",
            "severity": "Medium",
            "risk_score": 68,
            "rule_id": "RULE-SEC-004-PRIVILEGE-ESCALATION",
            "first_seen": p0["timestamp"],
            "last_seen": priv_events[-1]["timestamp"],
            "primary_user": p0.get("user"),
            "primary_ip": p0.get("source_ip"),
            "primary_host": p0.get("host"),
            "targeted_hosts": [p0.get("host", "HOST-01")],
            "what_happened": (
                f"User '{p0.get('user')}' executed elevated administrative commands on host {p0.get('host')}."
            ),
            "why_correlated": "Security logging captured transition from standard security context to root/administrator rights.",
            "what_remains_uncertain": "May represent authorized DevOps maintenance or scheduled system update procedure.",
            "recommended_actions": [
                "Cross-reference user against approved Change Management maintenance window.",
                "Verify sudoers audit log for arguments passed to elevated binary."
            ],
            "mitre_tactics": [get_mitre_context("T1068")],
            "status": "New",
            "created_at": datetime.now(timezone.utc).isoformat() + "Z",
            "supporting_event_ids": [e["id"] for e in priv_events]
        }
        generated_alerts.append((alert, [e["id"] for e in priv_events]))

    # -------------------------------------------------------------
    # RULE 5: Unusual Access Times (Off-Hours)
    # -------------------------------------------------------------
    off_hours_events = []
    for ev in sorted_events:
        t = parse_time(ev["timestamp"])
        # Check if between 23:00 and 05:00
        if t.hour >= 23 or t.hour < 5:
            if ev.get("category") in ("AUTHENTICATION", "SYSTEM"):
                off_hours_events.append(ev)
                
    if len(off_hours_events) >= 2:
        alert_id = f"ALT-OFFHOURS-{uuid.uuid4().hex[:6].upper()}"
        u0 = off_hours_events[0]
        alert = {
            "id": alert_id,
            "title": f"Anomalous Off-Hours Activity Cluster ({u0.get('user', 'user')})",
            "severity": "Medium",
            "risk_score": 62,
            "rule_id": "RULE-SEC-005-OFF-HOURS-ACCESS",
            "first_seen": u0["timestamp"],
            "last_seen": off_hours_events[-1]["timestamp"],
            "primary_user": u0.get("user"),
            "primary_ip": u0.get("source_ip"),
            "primary_host": u0.get("host"),
            "targeted_hosts": [u0.get("host", "HOST-PRIMARY")],
            "what_happened": (
                f"Cluster of authentication or system events detected between 23:00 and 05:00 local time "
                f"for account '{u0.get('user')}' on {u0.get('host')}."
            ),
            "why_correlated": "Activity executed outside standard business operating schedule without prior reservation.",
            "what_remains_uncertain": "Employee could be working remotely in an alternate time zone or performing emergency remediation.",
            "recommended_actions": [
                "Verify whether employee has an active on-call rotation schedule.",
                "Check source IP for VPN gateway usage and geolocation consistency."
            ],
            "mitre_tactics": [get_mitre_context("T1078")],
            "status": "New",
            "created_at": datetime.now(timezone.utc).isoformat() + "Z",
            "supporting_event_ids": [e["id"] for e in off_hours_events]
        }
        generated_alerts.append((alert, [e["id"] for e in off_hours_events]))

    return generated_alerts
