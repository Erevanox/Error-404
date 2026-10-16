"""
MITRE ATT&CK Knowledge Base and Ethical Guidance Module for TraceX.
Every mapping is provided with explicit epistemic modesty:
Mappings represent heuristic hypotheses for analyst validation, not mathematical proof of hostile intrusion.
"""

ETHICAL_DISCLAIMER = (
    "DEFENSIVE OBSERVATION NOTICE: MITRE ATT&CK technique associations provided by TraceX "
    "are hypothesis-generating heuristic indicators based on observed telemetry characteristics. "
    "A technique mapping does NOT establish confirmed hostile intent or attribution. Legitimate system "
    "administration, automated scheduled tasks, and benign software updates frequently display "
    "overlapping telemetry patterns. Human investigation and multi-source corroboration are required."
)

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt authentication into systems using credential guessing or spraying.",
        "detection_context": "Observed multiple consecutive authentication failures against a target account or from a single origin IP address within a compressed time frame.",
        "benign_explanations": [
            "User recently changed their domain password but has a cached credential on a mobile device or background service attempting retries.",
            "Misconfigured scheduled task, automation script, or backup service running with outdated credentials.",
            "Service account synchronization error across domain controllers."
        ],
        "investigation_checklist": [
            "Check if password expiration policy triggered around this timestamp.",
            "Determine if source IP originates from an internal workstation, corporate VPN, or external untrusted network.",
            "Inspect user's normal working hours and usual endpoint assignments."
        ]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Initial Access, Privilege Escalation",
        "tactic_id": "TA0005",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection_context": "Successful login event occurring immediately after an anomaly cluster (e.g. following multiple failed attempts or from an unusual source address).",
        "benign_explanations": [
            "User finally recalled their correct password after multiple incorrect typing attempts.",
            "Help Desk performed a self-service or assisted password reset during a live call.",
            "Legitimate remote work session initiated from a personal or non-standard laptop."
        ],
        "investigation_checklist": [
            "Verify with the account owner via phone or internal secure chat if they initiated this login.",
            "Review multi-factor authentication (MFA) challenge status (was push prompt approved or bypassed?).",
            "Examine subsequent commands executed in this authenticated session."
        ]
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Adversaries may use valid credentials to log into a service specifically designed to accept remote connections, such as SSH, SMB/Windows Admin Shares, or RDP.",
        "detection_context": "Single source workstation establishing sequential remote management connections (SMB port 445, SSH port 22, RDP port 3389) across multiple internal hosts.",
        "benign_explanations": [
            "IT System Administrator deploying software patches, troubleshooting servers, or running an inventory script.",
            "Internal vulnerability scanner or network management tool (e.g., Nessus, Ansible, SCCM) conducting periodic sweeps.",
            "Developer accessing test lab machines or database staging servers."
        ],
        "investigation_checklist": [
            "Check active Change Management or Maintenance Window tickets for this time window.",
            "Determine if the user's role normally includes server administration privileges.",
            "Inspect process tree on the destination host to identify which binaries were launched."
        ]
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by transferring it to an external server or service using a protocol different from the existing command and control channel.",
        "detection_context": "High-volume outbound data transfer (bytes_out spike) to an external or unfamiliar IP address.",
        "benign_explanations": [
            "Scheduled offsite database backup, cloud synchronization (OneDrive, Google Drive), or video conferencing session.",
            "Large media file or developer asset download/upload required for a legitimate project.",
            "Software update cache distribution or OS telemetry payload upload."
        ],
        "investigation_checklist": [
            "Inspect destination IP reputation (whois, ASN, threat intelligence feeds).",
            "Verify file path or process initiating the transfer (e.g., curl, python, backup agent vs cloud storage client).",
            "Compare byte volume against user's historical 30-day baseline."
        ]
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may exploit vulnerabilities to execute code at a higher privilege level on the system.",
        "detection_context": "Execution of sudo, administrator token manipulation, or sudden elevation from standard user to system privileges.",
        "benign_explanations": [
            "Authorized developer running sudo commands to install debugging packages.",
            "System administrator elevating privileges to install security patches or modify config files.",
            "Automation agent executing routine cron jobs requiring superuser permissions."
        ],
        "investigation_checklist": [
            "Check sudoers configuration and bash/zsh history for elevated session.",
            "Confirm if elevation matches an approved service request ticket.",
            "Review subsequent binary invocations for anomalous tools (netcat, mimikatz, powershell bypasses)."
        ]
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify exploitable targets.",
        "detection_context": "Burst of network connections from a single host targeting multiple distinct destination ports or IP addresses within seconds.",
        "benign_explanations": [
            "Network monitoring tool (e.g. Zabbix, PRTG, Nagios) performing service availability polling.",
            "Local service discovering network printers or media servers (mDNS, SSDP, UPnP).",
            "P2P application or distributed database node sync."
        ],
        "investigation_checklist": [
            "Determine if source IP matches designated network discovery appliances.",
            "Check destination port range (common administrative ports vs wide-range sweep).",
            "Inspect originating process on the source host."
        ]
    }
}

def get_mitre_context(technique_id: str):
    return MITRE_TECHNIQUES.get(technique_id, {
        "id": technique_id,
        "name": "Observed Security Anomaly",
        "tactic": "Investigation Needed",
        "tactic_id": "TA0000",
        "description": "Heuristic anomaly flagged by correlation rules.",
        "detection_context": "Pattern matched defined SOC detection threshold.",
        "benign_explanations": ["May represent authorized administrative activity or routine automation."],
        "investigation_checklist": ["Corroborate with system owner and cross-reference change tickets."]
    })
