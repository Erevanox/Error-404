# EventLens – Cybersecurity Incident Correlation & Visualization System

> **Tagline:** *"EventLens — Evidence First. Human Guided. Defensive by Design."*

EventLens is a modern, defensive Security Operations Center (SOC) intelligence and incident correlation platform. It synthesizes multi-source authentication, host process, and network telemetry to identify suspicious activity, correlate related events into explainable incident dossiers, and empower human analysts with epistemic clarity and automated visualization.

---

## 🛡️ Core Philosophy: Defensive by Design & Epistemic Modesty

EventLens adheres strictly to defensive blue-team principles:
1. **Preserve Raw Forensic Truth:** Every normalized event retains its verbatim, unmodified raw log string for legal and forensic chain-of-custody.
2. **Epistemic Modesty:** Correlation rules and risk scores generate **working investigative hypotheses**, never absolute proof of hostile intent. Legitimate administrative tasks, DevOps automation, and network glitches frequently mimic malicious activity.
3. **Simulated Response Actions:** All containment playbooks (host quarantine, session token revocation, null-route IP blocking) operate in **safe sandbox mode**, producing verified simulation audits without making destructive changes to live networks.
4. **Authorized & Synthetic Telemetry:** Operates exclusively on synthetic, sanitized, or authorized security log streams.

---

## 🏗️ Architecture & Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend UI** | **React 18**, **Tailwind CSS**, **Lucide React** (SOC dark navy palette `#070b14` with cyan/blue accents) |
| **Relationship Graph** | **React Flow (`reactflow`)** with custom nodes, animated threat vectors, and minimap |
| **Charts & Visualizations** | **Recharts** (Single Scatter Plot, categorical bar charts, severity distributions) |
| **Backend API** | **Python 3.12**, **FastAPI**, **Uvicorn** |
| **Database** | **SQLite** (`eventlens.db`) with tables for events, correlated alerts, cases, notes, audit trail, playbooks |
| **Report Generation** | **ReportLab Platypus** (Server-side PDF generation) + **jsPDF** (Client-side fallback) |
| **Data Formats** | **JSON** and **CSV** ingestion and export |

---

## ⚡ Main Features

### 1. SOC Dashboard
- Real-time operational metrics: **Total Events**, **Alerts Requiring Review**, **High-Concern Patterns**, and **Normal Telemetry**.
- Domain breakdown charts for **Authentication**, **System**, and **Network** streams.
- Incident severity distribution and immediate triage shortcuts.

### 2. Log Upload & Parser
- Ingests **CSV** and **JSON** logs with schema auto-detection and validation.
- Displays line-by-line parsing errors or format warnings.
- Quick-loaders for pre-built synthetic incident datasets.

### 3. Log Normalization Engine
- Unifies disparate log formats (Windows Event IDs 4624/4625/4688, Linux `/var/log/auth.log`, SSH, Sysmon, Zeek conn.log, Firewall traffic) into a common schema.
- Calculates numeric severity ratings on a **1.0 to 10.0 scale**.
- Preserves verbatim `raw_log` strings.

### 4. Detection & Correlation Engine
- Detects multi-stage attack patterns:
  - **Repeated Failed Logins** (Brute Force threshold $\ge 3$)
  - **Compromised Credential Access** (Successful login following failure spikes)
  - **Internal Lateral Movement** (Sequential remote connections across multiple internal hosts via SMB port 445 / SSH port 22)
  - **Unusual Access Times** (Off-hours logins between 23:00 and 05:00)
  - **Privilege Changes** (Sudo elevation and administrative rights changes)
  - **Anomalous Egress Transfers** (High-volume data spikes exceeding 20 MB)

### 5. Evidence-First Explainable Alerts
Every alert is structured across 6 clear dimensions:
1. **What Happened:** Technical and executive incident summary.
2. **Why Correlated:** Exact correlation criteria, temporal proximity, shared identity, and host pivot points.
3. **What Remains Uncertain:** Explicit false-positive hypotheses and benign alternative explanations.
4. **Supporting Evidence:** Clickable list of exact supporting logs linking directly into the Evidence Inspector.
5. **MITRE ATT&CK Context:** Associated tactics and techniques with detection rationale.
6. **Recommended Analyst Actions:** Actionable step-by-step SOC triage checklist.

### 6. Interactive Chronological Timeline
- Visual sequence of all related events with millisecond-accurate timestamps.
- Color-coded event category badges (Authentication in cyan, System in amber, Network in purple).
- Filterable by specific Correlated Alert or across the entire event stream.

### 7. Single Event Correlation Scatter Plot
- Displays **all ingested telemetry events in one interactive scatter plot**.
- **X-Axis:** Formatted chronological sequence/timestamp.
- **Y-Axis:** Numeric severity indicator (1.0 to 10.0 scale).
- **Categories:**
  - 🔵 **Authentication:** Cyan circles
  - 🟡 **System:** Amber squares
  - 🟣 **Network:** Purple triangles
- **Controls:** Minimum severity slider, category filter buttons, search input, and interactive tooltips.
- **Clickable:** Clicking any scatter point opens the event in the Evidence Inspector!

### 8. Relationship Traceback Graph
- Built with **React Flow**: visualizes the lateral attack path:
  $$\text{Origin IP } (192.168.1.105) \longrightarrow \text{User Account } (m.vasquez) \longrightarrow \text{Foothold Asset } (WORKSTATION-04) \longrightarrow \text{Internal Targets } (FILE-SRV02, PROD-DB01)$$
- Animated glowing edges with protocol labels (SMB, SSH, TLS egress).
- Interactive nodes: Click any entity to inspect attributes, IP reputation, and associated alerts.

### 9. Forensic Evidence Inspector
- Side-by-side view:
  - **Left:** Normalized unified event schema (Category, Action, User, IPs, Host, Port, Protocol, Bytes, Metadata).
  - **Right:** Original Raw Log (verbatim text in monospace terminal with **Copy Raw** button).

### 10. MITRE ATT&CK Matrix & Context
- Interactive matrix mapping: **T1110 (Brute Force)**, **T1078 (Valid Accounts)**, **T1021 (Remote Services)**, **T1068 (Privilege Escalation)**, and **T1048 (Exfiltration)**.
- Detailed breakdown of detection context, plausible benign explanations, and analyst verification checklists.

### 11. Case Management & Immutable Audit Trail
- Create investigation cases from alerts or manual entry.
- Update status: `Active`, `In Progress`, `Contained`, `False Positive`, `Resolved`.
- Add analyst investigation notes with persistent SQLite storage.
- Immutable audit log tracking case creations, status transitions, and note submissions.

### 12. Response Playbooks (Simulated Actions Only)
- Recommended containment steps:
  - *[Simulate] Revoke Active Session Tokens*
  - *[Simulate] EDR Endpoint Network Isolation*
  - *[Simulate] Enforce Out-of-Band Password Reset*
  - *[Simulate] Perimeter Null-Route IP Block*
  - *[Simulate] Volatile RAM Forensic Capture*
- Live simulation console logging dispatched actions with complete safety confirmation.

### 13. Investigation Reports & Data Exports
- **PDF Investigation Dossier:** Professional multi-page report generated via ReportLab Platypus.
- **CSV Evidence Export:** Complete download of normalized fields and raw logs for third-party SIEM analysis.

---

## 🎯 Canonical Demo Scenario

The application includes the canonical hackathon demonstration scenario:
1. **Oct 13 02:14:10 – 02:16:48:** Five consecutive authentication failures for user `m.vasquez` from `192.168.1.105` against `WORKSTATION-04` (Attempt 1 to 5).
2. **Oct 13 02:18:15:** Successful authentication accepted via password/PAM session.
3. **Oct 13 02:19:30:** PowerShell network connection discovery on `WORKSTATION-04`.
4. **Oct 13 02:22:10:** Lateral connection via SMB (port 445) to internal server `FILE-SRV02`.
5. **Oct 13 02:25:40:** Lateral connection via SSH (port 22) to internal database server `PROD-DB01`.
6. **Oct 13 02:28:12:** Privilege escalation via `sudo mysqldump` on `PROD-DB01`.
7. **Oct 13 02:34:00:** High-volume outbound data transfer (84 MB) to external IP `203.0.113.88`.
8. **Concurrent:** Normal baseline background traffic (nightly cron, DNS health check, routine engineer login).

**Result:** The correlation engine automatically synthesizes this sequence into a **Critical Correlated Alert** (`ALT-CORR-...`, Risk Score: 94/100) with complete traceback graphs, timeline stages, and explainability records.

---

## 🚀 Setup & Execution Instructions

### Prerequisites
- Node.js (v18+)
- Python (3.10+) with `uv`

### Running the Application

You can start both servers with the included batch file:
```cmd
start_eventlens.bat
```

Or start them manually in two terminals:

#### Terminal 1: Backend
```powershell
cd "c:\antigravity\trace x\backend"
uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

#### Terminal 2: Frontend
```powershell
cd "c:\antigravity\trace x\frontend"
node .\node_modules\vite\bin\vite.js --port 5173
```

- **Frontend SOC Dashboard:** `http://localhost:5173/`
- **Backend API & Health:** `http://127.0.0.1:8000/api/health`
- **Swagger Documentation:** `http://127.0.0.1:8000/docs`
