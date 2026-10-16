import React, { useState } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle2, Info, 
  HelpCircle, ExternalLink, ChevronRight, Terminal 
} from 'lucide-react';

const TACTICS_DATA = [
  {
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    techniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        status: 'Triggered (5 Attempts)',
        severity: 'High',
        description: 'Adversaries may use brute force techniques to attempt authentication into systems by guessing passwords or spraying credentials.',
        detectionContext: 'Observed 5 consecutive failed logins for user m.vasquez from 192.168.1.105 within 3 minutes.',
        benignExplanations: [
          'User recently updated their Active Directory password and a cached service or mobile device is sending expired credentials.',
          'Automation script or scheduled batch job misconfigured with outdated credentials.',
          'Kerberos / LDAP domain controller synchronization replication delay.'
        ],
        investigationChecklist: [
          'Check Domain Password Policy logs for recent password resets.',
          'Verify if the origin IP matches user workstation lease in DHCP.',
          'Inquire with the user if they were actively trying to log in at this timestamp.'
        ]
      }
    ]
  },
  {
    tactic: 'Initial Access / Defense Evasion',
    tacticId: 'TA0005',
    techniques: [
      {
        id: 'T1078',
        name: 'Valid Accounts',
        status: 'Triggered (Post-Failure)',
        severity: 'Critical',
        description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation.',
        detectionContext: 'Successful SSH/PAM authentication immediately following multiple password failures.',
        benignExplanations: [
          'User recalled password after multiple typographical mistakes.',
          'Help Desk performed a self-service password reset while user was on the phone.',
          'Legitimate off-hours remote maintenance performed by on-call engineer.'
        ],
        investigationChecklist: [
          'Verify multi-factor authentication (MFA) challenge outcome.',
          'Contact account owner via telephone or corporate chat out-of-band.',
          'Examine process execution telemetry on the authenticated host.'
        ]
      }
    ]
  },
  {
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    techniques: [
      {
        id: 'T1021',
        name: 'Remote Services',
        status: 'Triggered (Multi-Host)',
        severity: 'Critical',
        description: 'Adversaries may use valid credentials to log into a service specifically designed to accept remote connections, such as SSH, SMB, or RDP.',
        detectionContext: 'Origin workstation initiated SMB (port 445) to FILE-SRV02 and SSH (port 22) to PROD-DB01 in rapid succession.',
        benignExplanations: [
          'System administrator executing routine deployment or database maintenance across server tiers.',
          'Internal vulnerability scanner or asset inventory tool performing scheduled network discovery.',
          'DevOps automated CI/CD pipeline deploying code to staging.'
        ],
        investigationChecklist: [
          'Check IT Change Management portal for approved maintenance tickets.',
          'Verify if user role encompasses multi-server administration permissions.',
          'Inspect destination host process logs for anomalous script execution.'
        ]
      }
    ]
  },
  {
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    techniques: [
      {
        id: 'T1068',
        name: 'Exploitation for Privilege Escalation',
        status: 'Triggered (Sudo)',
        severity: 'Medium',
        description: 'Adversaries may exploit software vulnerabilities or abuse sudo configurations to elevate permissions.',
        detectionContext: 'Sudo invocation by standard user to run mysqldump with root permissions.',
        benignExplanations: [
          'Authorized database engineer performing manual emergency backup.',
          'Authorized deployment script running with root permissions per runbook.'
        ],
        investigationChecklist: [
          'Audit sudoers configuration on PROD-DB01.',
          'Confirm if mysqldump command was preceded by an approved ticket.'
        ]
      }
    ]
  },
  {
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    techniques: [
      {
        id: 'T1048',
        name: 'Exfiltration Over Alternative Protocol',
        status: 'Triggered (84MB Egress)',
        severity: 'High',
        description: 'Adversaries may steal sensitive data by transferring it to an external server over an unauthorized network channel.',
        detectionContext: 'Abrupt egress surge of 84 MB to external IP address 203.0.113.88 on port 443.',
        benignExplanations: [
          'Legitimate cloud backup synchronization or database replica snapshot upload.',
          'Large data set download or upload required for customer support ticket.'
        ],
        investigationChecklist: [
          'Perform WHOIS and Threat Intelligence lookup on 203.0.113.88.',
          'Inspect process ID initiating the TLS socket on the database server.',
          'Verify data loss prevention (DLP) alerts associated with destination.'
        ]
      }
    ]
  }
];

export default function MitreMatrix() {
  const [selectedTech, setSelectedTech] = useState(TACTICS_DATA[0].techniques[0]);

  return (
    <div className="space-y-4">
      {/* Header with Epistemic Modesty Notice */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 shadow-card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-[#1677C8]" />
              <h2 className="text-base font-bold text-[#252B33]">
                MITRE ATT&CK Matrix & Hypothesis Context
              </h2>
            </div>
            <p className="text-xs text-[#657180] max-w-3xl leading-relaxed">
              Mapped heuristic techniques for blue-team hypothesis testing. Mappings reflect behavioral similarities 
              and do not constitute definitive proof of hostile intrusion without corroboration.
            </p>
          </div>

          <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#F0F3F6] text-[#1677C8] border border-[#DDE3EA] uppercase font-semibold shrink-0">
            Enterprise Matrix v14
          </span>
        </div>

        {/* Ethical Notice Banner */}
        <div className="mt-4 p-3 rounded-lg bg-[#EAF3FB] border border-[#BFDBFE] text-[11px] text-[#252B33] flex items-start gap-2.5">
          <Info className="w-4 h-4 text-[#1677C8] shrink-0 mt-0.5" />
          <p className="leading-relaxed text-[#475569]">
            <strong className="text-[#1677C8]">Epistemic Modesty Principle:</strong> Correlation rules map observed actions to ATT&CK techniques as working investigative hypotheses. Legitimate administration (DevOps, updates, scheduled jobs) frequently generates identical telemetry.
          </p>
        </div>
      </div>

      {/* Interactive Matrix Columns */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
        {TACTICS_DATA.map((col) => (
          <div key={col.tacticId} className="bg-white border border-[#DDE3EA] rounded-xl overflow-hidden flex flex-col shadow-card">
            <div className="p-3 bg-[#F8FAFC] border-b border-[#DDE3EA]">
              <span className="text-[10px] font-mono text-[#1677C8] block font-semibold">{col.tacticId}</span>
              <h3 className="text-xs font-bold text-[#252B33] tracking-tight mt-0.5">{col.tactic}</h3>
            </div>

            <div className="p-2 space-y-2 flex-1">
              {col.techniques.map((tech) => {
                const isSelected = selectedTech?.id === tech.id;
                return (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTech(tech)}
                    className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#EAF3FB] border-[#1677C8] shadow-sm text-[#1677C8]'
                        : 'bg-[#F8FAFC] border-[#DDE3EA] hover:border-[#1677C8]/50 text-[#252B33]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                      <span className="text-[#1677C8] font-bold">{tech.id}</span>
                      <span className={`px-1 py-0.2 rounded font-bold ${
                        tech.severity === 'Critical' ? 'text-[#C53030]' :
                        tech.severity === 'High' ? 'text-[#DD6B20]' : 'text-[#D69E2E]'
                      }`}>
                        {tech.severity}
                      </span>
                    </div>
                    <div className="font-semibold text-xs text-[#252B33]">{tech.name}</div>
                    <div className="text-[10px] text-[#657180] mt-1 font-mono">
                      {tech.status}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Technique Forensic Details Card */}
      {selectedTech && (
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 space-y-4 shadow-card">
          <div className="flex items-center justify-between pb-3 border-b border-[#DDE3EA]">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-[#1677C8]">{selectedTech.id}</span>
                <h3 className="text-base font-bold text-[#252B33]">{selectedTech.name}</h3>
              </div>
              <p className="text-xs text-[#657180] mt-0.5">{selectedTech.description}</p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-[#F0F3F6] text-[#252B33] border border-[#DDE3EA] font-semibold">
              Severity: {selectedTech.severity}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            {/* Detection Context */}
            <div className="p-3.5 rounded-xl bg-[#F8FAFC] border border-[#DDE3EA]">
              <h4 className="font-bold text-[#1677C8] uppercase text-[11px] mb-1.5 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                <span>Detection Context</span>
              </h4>
              <p className="text-[#475569] leading-relaxed">{selectedTech.detectionContext}</p>
            </div>

            {/* Benign Alternative Hypotheses */}
            <div className="p-3.5 rounded-xl bg-[#FFFAF0] border border-[#FEEBC8]">
              <h4 className="font-bold text-[#DD6B20] uppercase text-[11px] mb-1.5 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5" />
                <span>Plausible Benign Hypotheses</span>
              </h4>
              <ul className="space-y-1.5 text-[#475569]">
                {selectedTech.benignExplanations.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-[#DD6B20] font-bold">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* SOC Verification Checklist */}
            <div className="p-3.5 rounded-xl bg-[#F0FDF4] border border-[#DCFCE7]">
              <h4 className="font-bold text-[#16A34A] uppercase text-[11px] mb-1.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>SOC Verification Checklist</span>
              </h4>
              <ul className="space-y-1.5 text-[#475569]">
                {selectedTech.investigationChecklist.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-[#16A34A] font-bold">[ ]</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
