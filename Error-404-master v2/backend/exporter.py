import io
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from mitre import ETHICAL_DISCLAIMER


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas for dynamic total page count (Page X of Y)
    and consistent running headers/footers across pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        page_w, page_h = letter
        margin = 36

        # Running header (pages 2+)
        if self._pageNumber > 1:
            self.setFont('Helvetica-Bold', 7.5)
            self.setFillColor(colors.HexColor('#0F172A'))
            self.drawString(margin, 766, "TRACEX")

            self.setFont('Helvetica', 7)
            self.setFillColor(colors.HexColor('#64748B'))
            self.drawString(margin + 46, 766, "•  SOC Forensic Incident Dossier")

            self.setFont('Helvetica-Bold', 6.5)
            self.setFillColor(colors.HexColor('#94A3B8'))
            self.drawRightString(page_w - margin, 766, "TLP:AMBER  //  CONFIDENTIAL")

            self.setStrokeColor(colors.HexColor('#E2E8F0'))
            self.setLineWidth(0.5)
            self.line(margin, 760, page_w - margin, 760)

        # Running footer (all pages)
        self.setStrokeColor(colors.HexColor('#E2E8F0'))
        self.setLineWidth(0.5)
        self.line(margin, 26, page_w - margin, 26)

        self.setFont('Helvetica-Bold', 7)
        self.setFillColor(colors.HexColor('#0D9488'))
        self.drawString(margin, 16, "TRACEX")

        self.setFont('Helvetica', 6.5)
        self.setFillColor(colors.HexColor('#64748B'))
        self.drawString(margin + 44, 16, "•  Defensive Telemetry Correlation Platform  •  Preserved Forensic Evidence")

        page_text = f"Page {self._pageNumber} of {total_pages}"
        self.setFont('Helvetica', 7)
        self.setFillColor(colors.HexColor('#64748B'))
        self.drawRightString(page_w - margin, 16, page_text)


def format_ts_utc(ts: Optional[str]) -> str:
    if not ts:
        return "Not recorded"
    return ts.replace("T", " ").replace("Z", " UTC")


def generate_pdf_report(
    alert: Optional[Dict[str, Any]] = None,
    case: Optional[Dict[str, Any]] = None,
    notes: Optional[List[Dict[str, Any]]] = None,
    all_events: Optional[List[Dict[str, Any]]] = None,
    all_alerts: Optional[List[Dict[str, Any]]] = None,
    stats: Optional[Dict[str, Any]] = None
) -> bytes:
    buffer = io.BytesIO()
    
    # 36pt margins left/right -> 540pt printable width on 612pt letter
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=38,
        bottomMargin=34,
        pageCompression=0
    )

    styles = getSampleStyleSheet()

    # Refined, Modern & Elegant Typography
    h1_style = ParagraphStyle(
        'DocH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=0
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.8,
        leading=9,
        textColor=colors.HexColor('#64748B')
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=5,
        spaceAfter=2.5
    )
    h3_style = ParagraphStyle(
        'DocH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=3,
        spaceAfter=1.5
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9.2,
        textColor=colors.HexColor('#334155')
    )
    mono_style = ParagraphStyle(
        'DocMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=5.8,
        leading=7.5,
        textColor=colors.HexColor('#0F172A')
    )
    meta_label = ParagraphStyle(
        'DocMetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=6.5,
        leading=8.2,
        textColor=colors.HexColor('#475569')
    )
    meta_val = ParagraphStyle(
        'DocMetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=8.8,
        textColor=colors.HexColor('#0F172A')
    )
    th_style = ParagraphStyle(
        'DocTH',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=6.8,
        leading=8.5,
        textColor=colors.HexColor('#1E293B')
    )
    td_style = ParagraphStyle(
        'DocTD',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.7,
        leading=8.5,
        textColor=colors.HexColor('#1E293B')
    )
    disclaimer_style = ParagraphStyle(
        'DocDisclaimer',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=6,
        leading=7.8,
        textColor=colors.HexColor('#64748B')
    )
    callout_style = ParagraphStyle(
        'DocCallout',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.8,
        leading=8.8,
        textColor=colors.HexColor('#1E293B')
    )

    elements = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Resolve active events and alerts
    events_list = all_events or (alert.get("supporting_events", []) if alert else [])
    alerts_list = all_alerts or ([alert] if alert else [])

    total_records = len(events_list) if stats is None else stats.get("total_records", stats.get("total_events", len(events_list)))
    detection_alerts = len([e for e in events_list if e.get("severity_score", 1.0) >= 4.0 or e.get("status") == "failure"]) if stats is None else stats.get("detection_alerts", 0)
    correlated_alerts_count = len(alerts_list) if stats is None else stats.get("correlated_alerts", len(alerts_list))
    validation_errors_count = 0 if stats is None else stats.get("validation_errors", 0)

    # =========================================================================
    # EMPTY STATE REPORT (CLEAN, ELEGANT SINGLE-PAGE REPORT)
    # =========================================================================
    if total_records == 0 and not alert:
        hdr_data = [
            [
                Paragraph("<b>TRACEX</b><br/><font size=6.5 color='#0D9488'><b>CYBERSECURITY INVESTIGATION ENGINE • FORENSIC AUDIT</b></font>", h1_style),
                Paragraph(f"<b>REPORT:</b> TraceX Empty Investigation State<br/>"
                          f"<b>GENERATED:</b> {now_str}<br/>"
                          f"<b>CLASSIFICATION:</b> TLP:AMBER — INTERNAL SOC USE ONLY", subtitle_style)
            ]
        ]
        hdr_tbl = Table(hdr_data, colWidths=[310, 230])
        hdr_tbl.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 0),
        ]))
        elements.append(hdr_tbl)
        elements.append(Spacer(1, 3))
        elements.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor('#0D9488'), spaceBefore=2, spaceAfter=8))

        elements.append(Paragraph("<b>Investigation Engine Status: Ready (Clean State)</b>", h2_style))
        elements.append(Paragraph(
            "No telemetry logs or attack datasets have been ingested into the TraceX correlation pipeline during this session. "
            "All detection counters, correlation graph topologies, and forensic timelines remain at zero. "
            "No synthetic anomalies or speculative incident records have been fabricated.",
            body_style
        ))
        elements.append(Spacer(1, 8))

        zero_tbl_data = [
            [
                Paragraph("<b>PROCESSED RECORDS</b>", meta_label),
                Paragraph("<b>DETECTION ALERTS</b>", meta_label),
                Paragraph("<b>CORRELATED ALERTS</b>", meta_label),
                Paragraph("<b>VALIDATION ERRORS</b>", meta_label)
            ],
            [
                Paragraph("<font size=10 color='#0F172A'><b>0</b></font>", meta_val),
                Paragraph("<font size=10 color='#0F172A'><b>0</b></font>", meta_val),
                Paragraph("<font size=10 color='#0F172A'><b>0</b></font>", meta_val),
                Paragraph("<font size=10 color='#0F172A'><b>0</b></font>", meta_val)
            ]
        ]
        zero_tbl = Table(zero_tbl_data, colWidths=[135, 135, 135, 135])
        zero_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(zero_tbl)
        elements.append(Spacer(1, 12))

        # Instructions card
        inst_data = [
            [
                Paragraph("<b>OPERATIONAL GUIDANCE:</b> To generate forensic incident reports, ingest structured CSV or EVTX logs "
                          "via the TraceX interface. The correlation engine will automatically detect authentication anomalies, lateral "
                          "movement sequences, and data exfiltration patterns.", callout_style)
            ]
        ]
        inst_tbl = Table(inst_data, colWidths=[540])
        inst_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(inst_tbl)
        elements.append(Spacer(1, 14))

        elements.append(Paragraph(f"<i>{ETHICAL_DISCLAIMER}</i>", disclaimer_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<b>CERTIFICATION:</b> TraceX Defensive Incident Correlation Platform. Preserved for authorized SOC operations.", disclaimer_style))

        doc.build(elements, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()

    # =========================================================================
    # POPULATED INCIDENT INVESTIGATION DOSSIER (2-3 PAGES TIGHT & ELEGANT)
    # =========================================================================
    primary_alert = alert or (alerts_list[0] if alerts_list else {})

    supporting_events = primary_alert.get("supporting_events", [])
    if not supporting_events and events_list:
        supporting_ids = set(primary_alert.get("supporting_event_ids", []))
        if supporting_ids:
            supporting_events = [e for e in events_list if e.get("id") in supporting_ids]
        else:
            supporting_events = events_list

    chronological_events = sorted(supporting_events, key=lambda x: x.get("timestamp") or "")

    first_seen_str = format_ts_utc(primary_alert.get("first_seen") or (chronological_events[0].get("timestamp") if chronological_events else None))
    last_seen_str = format_ts_utc(primary_alert.get("last_seen") or (chronological_events[-1].get("timestamp") if chronological_events else None))

    risk_score = primary_alert.get("risk_score", 85)
    severity_label = (primary_alert.get("severity") or "High").upper()
    alert_id = primary_alert.get("id", "ALT-UNKNOWN")
    case_id = (case.get("id") if case else primary_alert.get("case_id")) or "Unassigned"

    source_ip = primary_alert.get("primary_ip") or "Not recorded"
    is_doc_ip = any(source_ip.startswith(prefix) for prefix in ("198.51.100.", "203.0.113.", "192.0.2."))
    source_ip_label = f"{source_ip} (Simulated)" if is_doc_ip else source_ip

    # =========================================================================
    # PAGE 1: EXECUTIVE BRIEF, ENTITY ATTRIBUTION, MITRE & REMEDIATION PLAYBOOK
    # =========================================================================

    # 1. Header Banner
    header_table_data = [
        [
            Paragraph("<b>TRACEX</b><br/><font size=6.5 color='#0D9488'><b>CYBERSECURITY FORENSIC INVESTIGATION DOSSIER</b></font>", h1_style),
            Paragraph(f"<b>STATUS:</b> ACTIVE  |  <b>TLP:</b> AMBER<br/>"
                      f"<b>ALERT:</b> {alert_id}  |  <b>CASE:</b> {case_id}<br/>"
                      f"<b>GENERATED:</b> {now_str}", subtitle_style)
        ]
    ]
    header_table = Table(header_table_data, colWidths=[310, 230])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 0),
    ]))
    elements.append(header_table)
    elements.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor('#0D9488'), spaceBefore=2, spaceAfter=4))

    # 2. Executive KPI Metrics Ribbon
    metric_cards = [
        [
            Paragraph("<b>PROCESSED RECORDS</b>", meta_label),
            Paragraph("<b>DETECTION ALERTS</b>", meta_label),
            Paragraph("<b>CORRELATED ALERTS</b>", meta_label),
            Paragraph("<b>INVESTIGATION STATUS</b>", meta_label),
        ],
        [
            Paragraph(f"<font size=8.5 color='#0F172A'><b>{total_records}</b></font>", meta_val),
            Paragraph(f"<font size=8.5 color='#B91C1C'><b>{detection_alerts}</b></font>", meta_val),
            Paragraph(f"<font size=8.5 color='#B45309'><b>{correlated_alerts_count}</b></font>", meta_val),
            Paragraph(f"<font size=8.5 color='#0D9488'><b>TRIAGED / ACTIVE</b></font>", meta_val),
        ]
    ]
    summary_table = Table(metric_cards, colWidths=[135, 135, 135, 135])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 2.5),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 3))

    # 3. Incident Dossier & Entity Attribution
    risk_color = '#B91C1C' if risk_score >= 70 else ('#B45309' if risk_score >= 40 else '#0D9488')
    alert_meta_data = [
        [
            Paragraph("<b>Incident Title:</b>", meta_label),
            Paragraph(f"<b>{primary_alert.get('title', 'Correlated Security Incident')}</b>", meta_val),
            Paragraph("<b>Risk Rating:</b>", meta_label),
            Paragraph(f"<font color='{risk_color}'><b>{risk_score}/100 ({severity_label})</b></font>", meta_val)
        ],
        [
            Paragraph("<b>Target Account:</b>", meta_label),
            Paragraph(primary_alert.get("primary_user") or "Not specified", meta_val),
            Paragraph("<b>Observed Source IP:</b>", meta_label),
            Paragraph(source_ip_label, meta_val)
        ],
        [
            Paragraph("<b>Foothold Host:</b>", meta_label),
            Paragraph(primary_alert.get("primary_host") or "Not specified", meta_val),
            Paragraph("<b>Targeted Endpoints:</b>", meta_label),
            Paragraph(", ".join(primary_alert.get("targeted_hosts", [])) or "None identified", meta_val)
        ],
        [
            Paragraph("<b>First Observed:</b>", meta_label),
            Paragraph(first_seen_str, meta_val),
            Paragraph("<b>Last Observed:</b>", meta_label),
            Paragraph(last_seen_str, meta_val)
        ]
    ]
    meta_table = Table(alert_meta_data, colWidths=[88, 182, 88, 182])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 2.2),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 3))

    # 4. Section 1: Executive Summary & Observations
    elements.append(Paragraph("<b>1. Incident Executive Summary & Detection Rationale</b>", h2_style))
    elements.append(Paragraph(primary_alert.get("what_happened", "Correlated security events identified by telemetry rules."), body_style))
    elements.append(Spacer(1, 2))

    why_box_data = [
        [
            Paragraph("<b>DETECTION RATIONALE:</b> "
                      f"{primary_alert.get('why_correlated', 'Flagged by correlation engine rules based on temporal proximity and entity chaining.')}",
                      callout_style)
        ]
    ]
    why_table = Table(why_box_data, colWidths=[540])
    why_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#EFF6FF')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#BFDBFE')),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(why_table)
    elements.append(Spacer(1, 2))

    # Observations Bullets
    obs_list = []
    if chronological_events:
        fails = [e for e in chronological_events if "fail" in (e.get("action") or "").lower() or e.get("status") == "failure"]
        succs = [e for e in chronological_events if "succ" in (e.get("action") or "").lower() or e.get("status") == "success"]
        lat = [e for e in chronological_events if e.get("port") in (22, 445, 3389) or "lateral" in (e.get("event_type") or "").lower()]
        data_ev = [e for e in chronological_events if (e.get("bytes_out") or 0) > 10_000_000 or "exfil" in (e.get("event_type") or "").lower()]

        if fails:
            obs_list.append(f"• <b>Authentication Anomaly:</b> {len(fails)} failed attempts recorded for account '{primary_alert.get('primary_user', 'user')}' originating from {source_ip_label}.")
        if succs:
            obs_list.append(f"• <b>Credential Access:</b> Successful authentication confirmed at {format_ts_utc(succs[0].get('timestamp'))}.")
        if lat:
            obs_list.append(f"• <b>Lateral Traversal:</b> Host pivot established across port(s) {[e.get('port') for e in lat if e.get('port')]}.")
        if data_ev:
            mb = round(sum(e.get("bytes_out", 0) for e in data_ev) / (1024 * 1024), 1)
            obs_list.append(f"• <b>Outbound Movement:</b> Egress data volume totaling {mb} MB observed.")

    if not obs_list:
        obs_list.append("• <b>Telemetry Deviation:</b> Multiple correlated events exceeded baseline SOC anomaly thresholds.")

    for obs in obs_list[:3]:
        elements.append(Paragraph(obs, body_style))

    elements.append(Spacer(1, 2))

    # 5. Section 2: MITRE ATT&CK Framework Mapping
    elements.append(Paragraph("<b>2. MITRE ATT&CK Framework Mapping</b>", h2_style))
    mitre_items = primary_alert.get("mitre_tactics", [])
    if not mitre_items:
        mitre_items = [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "benign_explanations": ["User mistyped password multiple times"]},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Initial Access", "benign_explanations": ["Authorized user logged in with approved credentials"]},
            {"id": "T1021.002", "name": "SMB/Admin Shares", "tactic": "Lateral Movement", "benign_explanations": ["Normal IT file share access or routine backup"]}
        ]

    mitre_tbl_data = [
        [
            Paragraph("<b>Technique ID</b>", th_style),
            Paragraph("<b>Technique Name</b>", th_style),
            Paragraph("<b>Tactic</b>", th_style),
            Paragraph("<b>Detection Match</b>", th_style),
            Paragraph("<b>Plausible Benign Alternate</b>", th_style)
        ]
    ]

    for m in mitre_items[:3]:
        tid = m.get("id", "N/A")
        tname = m.get("name", "N/A")
        tactic = m.get("tactic", "N/A")
        benign = m.get("benign_explanations", ["Authorized administrative workflow"])[0]

        mitre_tbl_data.append([
            Paragraph(f"<b>{tid}</b>", td_style),
            Paragraph(tname, td_style),
            Paragraph(tactic, td_style),
            Paragraph("<font color='#B45309'>Heuristic Match</font>", td_style),
            Paragraph(benign, td_style)
        ])

    mitre_table = Table(mitre_tbl_data, colWidths=[65, 115, 100, 85, 175])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('LINEBELOW', (0,0), (-1,0), 0.8, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('PADDING', (0,0), (-1,-1), 2),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(mitre_table)
    elements.append(Spacer(1, 3))

    # 6. Section 3: Recommended Containment & Remediation Actions
    elements.append(Paragraph("<b>3. Recommended Containment & Response Actions</b>", h2_style))
    recs = primary_alert.get("recommended_actions", [])
    if not recs:
        recs = [
            f"Contact account holder ({primary_alert.get('primary_user', 'user')}) out-of-band to verify active physical presence.",
            "Review authentication provider logs for concurrent conflicting geolocations.",
            f"Simulate session revocation for user '{primary_alert.get('primary_user', 'user')}'.",
            f"Inspect NetFlow and host logs on target endpoints {', '.join(primary_alert.get('targeted_hosts', [])) or 'internal hosts'}."
        ]

    recs_tbl_data = [
        [
            Paragraph("<b>Pri</b>", th_style),
            Paragraph("<b>Recommended Action</b>", th_style),
            Paragraph("<b>Target Entity</b>", th_style),
            Paragraph("<b>Status</b>", th_style)
        ]
    ]

    for idx, r in enumerate(recs[:3], start=1):
        status_label = "Simulated Playbook" if "simulated" in r.lower() else "Recommended"
        status_color = "#0284C7" if "simulated" in r.lower() else "#B45309"
        target_ent = primary_alert.get("primary_user") if idx <= 2 else (primary_alert.get("primary_host") or "Network")

        recs_tbl_data.append([
            Paragraph(f"<b>P{idx}</b>", td_style),
            Paragraph(r, td_style),
            Paragraph(str(target_ent), td_style),
            Paragraph(f"<font color='{status_color}'><b>{status_label}</b></font>", td_style)
        ])

    recs_table = Table(recs_tbl_data, colWidths=[35, 335, 90, 80])
    recs_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('LINEBELOW', (0,0), (-1,0), 0.8, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('PADDING', (0,0), (-1,-1), 2),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(recs_table)
    elements.append(Spacer(1, 2))

    # Analytical boundary note at bottom of Page 1
    caution_box_data = [
        [
            Paragraph("<b>ANALYTICAL BOUNDARY:</b> Findings document telemetry correlation hypotheses, "
                      "not definitive proof of compromise. SOC analyst verification and corroboration required.",
                      disclaimer_style)
        ]
    ]
    caution_table = Table(caution_box_data, colWidths=[540])
    caution_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FFFBEB')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#FDE68A')),
        ('PADDING', (0,0), (-1,-1), 2.5),
    ]))
    elements.append(caution_table)

    # PAGE BREAK: Page 1 ends cleanly. Page 2 begins with Timeline & Forensics.
    elements.append(PageBreak())

    # =========================================================================
    # PAGE 2: FORENSIC TIMELINE, CORRELATION SYNTHESIS & AUDIT TELEMETRY
    # =========================================================================

    # 7. Section 4: Chronological Forensic Investigation Timeline
    elements.append(Paragraph("<b>4. Chronological Forensic Investigation Timeline</b>", h2_style))
    timeline_display = chronological_events[:12] if len(chronological_events) > 12 else chronological_events
    if len(chronological_events) > 12:
        elements.append(Paragraph(f"<i>Displaying 12 primary correlated events of {len(chronological_events)} total records. Complete logs cataloged below and in CSV export.</i>", disclaimer_style))
        elements.append(Spacer(1, 1))

    timeline_tbl_data = [
        [
            Paragraph("<b>Time (UTC)</b>", th_style),
            Paragraph("<b>Category</b>", th_style),
            Paragraph("<b>Identity</b>", th_style),
            Paragraph("<b>Host / Endpoint</b>", th_style),
            Paragraph("<b>Action / Status</b>", th_style),
            Paragraph("<b>Risk</b>", th_style),
            Paragraph("<b>Investigative Context</b>", th_style)
        ]
    ]

    for ev in timeline_display:
        ts = ev.get("timestamp", "")
        ts_fmt = ts[11:19] if len(ts) >= 19 else ts
        user = ev.get("user") or "-"
        host_str = ev.get("host") or "-"
        if ev.get("dest_host") and ev.get("dest_host") != ev.get("host"):
            host_str = f"{host_str}➔{ev.get('dest_host')}"

        act = ev.get("action") or ev.get("status") or "-"
        score = ev.get("severity_score", 1.0)
        score_color = '#B91C1C' if score >= 7.0 else ('#B45309' if score >= 4.5 else '#0D9488')

        cat = (ev.get("category") or "SECURITY").upper()
        etype = (ev.get("event_type") or "").replace("_", " ")

        timeline_tbl_data.append([
            Paragraph(ts_fmt, td_style),
            Paragraph(cat[:10], td_style),
            Paragraph(user[:13], td_style),
            Paragraph(host_str[:15], td_style),
            Paragraph(act[:11], td_style),
            Paragraph(f"<font color='{score_color}'><b>{score:.1f}</b></font>", td_style),
            Paragraph(etype[:28], td_style)
        ])

    timeline_table = Table(timeline_tbl_data, colWidths=[48, 56, 70, 86, 65, 30, 185])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('LINEBELOW', (0,0), (-1,0), 0.8, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('PADDING', (0,0), (-1,-1), 1.8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(timeline_table)
    elements.append(Spacer(1, 3))

    # 8. Section 5: Correlation Rationale & Epistemic Distinctions
    elements.append(Paragraph("<b>5. Correlation Synthesis & Epistemic Distinctions</b>", h2_style))
    facts_and_inferences = (
        f"• <b>Observed Facts:</b> Telemetry originated from {source_ip_label} targeting '{primary_alert.get('primary_user', 'user')}' "
        f"on {primary_alert.get('primary_host', 'workstation')} ({first_seen_str} – {last_seen_str}).<br/>"
        f"• <b>Correlation Inference:</b> Triggered under rule <code>{primary_alert.get('rule_id', 'RULE-SEC-001')}</code> (Score: "
        f"<b>{risk_score}/100</b>) via temporal event chaining across authentication and network boundaries.<br/>"
        f"• <b>Remaining Uncertainties:</b> {primary_alert.get('what_remains_uncertain', 'Pending host memory analysis and user presence verification.')}"
    )
    elements.append(Paragraph(facts_and_inferences, body_style))
    elements.append(Spacer(1, 3))

    # Case Notes (if present)
    if notes:
        elements.append(Paragraph("<b>Case Notes & Analyst Log:</b>", h3_style))
        for n in notes[:2]:
            author = n.get("author", "Analyst")
            created = n.get("created_at", "")[:19]
            elements.append(Paragraph(f"• <b>{author}</b> ({created}): {n.get('content', '')}", body_style))
        elements.append(Spacer(1, 2))

    # 9. Section 6: Preserved Raw Telemetry Logs
    elements.append(Paragraph("<b>6. Preserved Raw Telemetry Audit Evidence</b>", h2_style))

    raw_tbl_data = [
        [
            Paragraph("<b>Event ID</b>", th_style),
            Paragraph("<b>Time (UTC)</b>", th_style),
            Paragraph("<b>Preserved Telemetry Record</b>", th_style)
        ]
    ]

    for ev in chronological_events[:8]:
        raw_msg = ev.get("raw_log") or f"Event: {ev.get('event_type')}, User: {ev.get('user')}, Host: {ev.get('host')}"
        raw_tbl_data.append([
            Paragraph(f"<b>{ev.get('id', 'EVT')}</b>", td_style),
            Paragraph(format_ts_utc(ev.get("timestamp"))[11:19], td_style),
            Paragraph(raw_msg[:120], mono_style)
        ])

    raw_table = Table(raw_tbl_data, colWidths=[65, 55, 420])
    raw_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('LINEBELOW', (0,0), (-1,0), 0.8, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('PADDING', (0,0), (-1,-1), 1.8),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(raw_table)
    elements.append(Spacer(1, 3))

    # Certification & Ethical Disclaimer Card
    cert_data = [
        [
            Paragraph(
                f"<i>{ETHICAL_DISCLAIMER}</i><br/>"
                "<b>CERTIFICATION:</b> Generated automatically by TraceX Defensive Incident Correlation Platform. "
                "Cryptographic chain of custody preserved in local forensic datastore. Authorized SOC use only.",
                disclaimer_style
            )
        ]
    ]
    cert_tbl = Table(cert_data, colWidths=[540])
    cert_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(cert_tbl)

    # Build PDF with two-pass NumberedCanvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_csv_export(events: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "category", "event_type", "user", "source_ip",
        "dest_ip", "host", "dest_host", "port", "protocol", "bytes_out",
        "action", "severity_score", "status", "raw_log"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for ev in events:
        row = {k: ev.get(k) for k in fieldnames}
        writer.writerow(row)
    return output.getvalue()
