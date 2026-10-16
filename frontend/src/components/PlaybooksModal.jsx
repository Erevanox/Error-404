import React, { useState, useEffect } from 'react';
import {
  X, BookOpen, Shield, Activity, Lock, Terminal,
  CheckCircle2, History, AlertTriangle, Cpu, Globe,
  ChevronRight, ThumbsUp, ThumbsDown, HelpCircle, ExternalLink
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function PlaybooksModal({ isOpen, onClose, defaultTarget }) {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState('steps'); // 'steps' | 'history'
  const [selectedStep, setSelectedStep] = useState(null);
  const [target, setTarget] = useState(defaultTarget || 'm.vasquez');
  const [loading, setLoading] = useState(false);
  const [outcome, setOutcome] = useState(null); // 'suspicious' | 'benign' | 'inconclusive' | null
  const [history, setHistory] = useState([]);
  const [consoleLog, setConsoleLog] = useState([]);

  const INVESTIGATION_STEPS = [
    {
      id: 'revoke_tokens',
      title: 'Check for Stolen Session Tokens',
      category: 'Identity',
      whatItDoes: 'Looks for signs that an attacker is using a valid login cookie or token to impersonate a real user — without needing their password.',
      whyItMatters: 'Attackers often steal session tokens after a successful phishing attack to bypass two-factor authentication.',
      checkThese: [
        'Look for the same account logging in from two very different IP addresses within minutes.',
        'Check if a session was opened at an unusual hour (e.g. 3 AM).',
        'See if the user\'s browser or device suddenly changed.',
      ],
      defaultTarget: 'm.vasquez',
      icon: Lock,
      color: '#1677C8',
      bg: '#EAF3FB',
      playbookId: 'revoke_tokens',
    },
    {
      id: 'quarantine_host',
      title: 'Isolate a Compromised Machine',
      category: 'Asset',
      whatItDoes: 'Simulates cutting off a workstation or server from the network so an attacker cannot keep using it as a base.',
      whyItMatters: 'Once a machine is compromised, the attacker may use it to jump to other systems (called lateral movement). Isolation stops the spread.',
      checkThese: [
        'Check if the machine made new outbound connections after the suspicious event.',
        'Look for unusual processes or services started around the same time.',
        'Verify if anyone legitimately logged into this machine at that time.',
      ],
      defaultTarget: 'WORKSTATION-04',
      icon: Cpu,
      color: '#6B46C1',
      bg: '#F3E8FF',
      playbookId: 'quarantine_host',
    },
    {
      id: 'force_password_reset',
      title: 'Force an Account Password Reset',
      category: 'Identity',
      whatItDoes: 'Simulates requiring a user to immediately change their password — useful when you suspect their credentials were leaked or guessed.',
      whyItMatters: 'Leaked passwords (from breached databases or phishing) let attackers log in repeatedly. A forced reset blocks them.',
      checkThese: [
        'Did the account appear in any known breach databases recently?',
        'Were there multiple failed login attempts before a success?',
        'Did the login come from an unexpected location or device?',
      ],
      defaultTarget: 'm.vasquez',
      icon: Shield,
      color: '#D69E2E',
      bg: '#FEFCBF',
      playbookId: 'force_password_reset',
    },
    {
      id: 'block_ip',
      title: 'Block a Suspicious IP Address',
      category: 'Network',
      whatItDoes: 'Simulates adding a firewall rule to drop all traffic to or from a specific IP address that appears malicious.',
      whyItMatters: 'If an attacker controls a specific IP (called a C2 server), blocking it cuts off their ability to send commands or receive stolen data.',
      checkThese: [
        'Search the IP on VirusTotal or AbuseIPDB to see if it has a bad reputation.',
        'Count how many internal machines connected to this IP.',
        'Check what time the connections occurred and how much data was transferred.',
      ],
      defaultTarget: '203.0.113.88',
      icon: Globe,
      color: '#C53030',
      bg: '#FEF2F2',
      playbookId: 'block_ip',
    },
    {
      id: 'snapshot_memory',
      title: 'Capture a Memory Snapshot for Forensics',
      category: 'Forensics',
      whatItDoes: 'Simulates taking a live dump of a machine\'s RAM — which may contain passwords, encryption keys, or malware that has not touched the disk.',
      whyItMatters: 'Many modern attacks run entirely in memory (called fileless malware) and disappear when the machine reboots. A snapshot preserves evidence.',
      checkThese: [
        'Are there suspicious processes running with no corresponding file on disk?',
        'Is any process injecting code into another (e.g. svchost.exe spawning unexpected children)?',
        'Have any encryption keys or credentials appeared in running processes?',
      ],
      defaultTarget: 'PROD-DB01',
      icon: Terminal,
      color: '#16A34A',
      bg: '#ECFDF5',
      playbookId: 'snapshot_memory',
    },
  ];

  useEffect(() => {
    if (activeTab === 'history') {
      apiClient.getPlaybookHistory().then(res => setHistory(res.history || [])).catch(console.error);
    }
  }, [activeTab]);

  const handleSimulate = async () => {
    if (!selectedStep || !target.trim()) return;
    setLoading(true);
    setOutcome(null);

    const logEntry = {
      timestamp: new Date().toLocaleTimeString(),
      text: `Running: "${selectedStep.title}" on '${target}'…`,
      type: 'info',
    };
    setConsoleLog(prev => [logEntry, ...prev]);

    try {
      const res = await apiClient.simulatePlaybook({
        playbook_id: `pb-${selectedStep.playbookId}`,
        playbook_name: selectedStep.title,
        action_name: selectedStep.playbookId,
        target: target,
        parameters: { environment: 'Sandbox', auth_level: 'SOC Tier 2' },
        analyst: 'SOC Lead Analyst',
      });
      setConsoleLog(prev => [{
        timestamp: new Date().toLocaleTimeString(),
        text: `[DONE]: ${res.simulation_result}`,
        type: 'success',
      }, ...prev]);
    } catch (err) {
      setConsoleLog(prev => [{
        timestamp: new Date().toLocaleTimeString(),
        text: `[ERROR]: ${err.message}`,
        type: 'error',
      }, ...prev]);
    } finally {
      setLoading(false);
    }
  };

  const active = selectedStep
    ? INVESTIGATION_STEPS.find(s => s.id === selectedStep)
    : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-white border border-[#DDE3EA] rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col text-[#252B33]">
        {/* Header */}
        <div className="p-5 border-b border-[#DDE3EA] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#EAF3FB] text-[#1677C8]">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#252B33] tracking-tight">
                Recommended Investigation Steps
              </h2>
              <p className="text-xs text-[#657180]">
                Guided steps to help you understand and respond to suspicious activity.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-[#657180] hover:text-[#252B33] bg-[#F0F3F6] hover:bg-[#E2E8F0] transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="px-5 pt-3 border-b border-[#DDE3EA] flex gap-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab('steps')}
            className={`pb-2.5 border-b-2 transition ${
              activeTab === 'steps'
                ? 'border-[#1677C8] text-[#1677C8] font-semibold'
                : 'border-transparent text-[#657180] hover:text-[#252B33]'
            }`}
          >
            Investigation Steps
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`pb-2.5 border-b-2 transition ${
              activeTab === 'history'
                ? 'border-[#1677C8] text-[#1677C8] font-semibold'
                : 'border-transparent text-[#657180] hover:text-[#252B33]'
            }`}
          >
            Simulation Audit Log
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 max-h-[72vh] overflow-y-auto text-xs">
          {activeTab === 'steps' ? (
            <>
              {/* Step selector cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {INVESTIGATION_STEPS.map((step) => {
                  const Icon = step.icon;
                  const isSelected = selectedStep === step.id;
                  return (
                    <button
                      key={step.id}
                      onClick={() => { setSelectedStep(step.id); setOutcome(null); setTarget(step.defaultTarget); }}
                      className={`p-3 rounded-xl border text-left transition-all ${
                        isSelected
                          ? 'ring-2 ring-offset-1 ring-[#1677C8] border-[#1677C8]'
                          : 'border-[#DDE3EA] bg-[#F8FAFC] hover:border-[#1677C8]/50 hover:bg-white'
                      }`}
                      style={{ backgroundColor: isSelected ? step.bg : undefined }}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white text-[#475569] border border-[#DDE3EA] font-semibold">
                          {step.category}
                        </span>
                        <Icon className="w-4 h-4" style={{ color: step.color }} />
                      </div>
                      <h4 className="font-bold text-[#252B33] text-[11px] leading-snug">{step.title}</h4>
                    </button>
                  );
                })}
              </div>

              {/* Detail panel for selected step */}
              {active && (
                <div className="rounded-xl border border-[#DDE3EA] overflow-hidden">
                  {/* Step header */}
                  <div className="px-4 py-3 flex items-center gap-2 border-b border-[#DDE3EA]" style={{ backgroundColor: active.bg }}>
                    <active.icon className="w-4 h-4 shrink-0" style={{ color: active.color }} />
                    <span className="font-bold text-[#252B33]">{active.title}</span>
                  </div>
                  <div className="p-4 space-y-4 bg-white">
                    {/* Plain-English explanation */}
                    <div className="space-y-1">
                      <p className="text-[11px] font-semibold text-[#475569] uppercase tracking-wider">What this step does</p>
                      <p className="text-xs text-[#252B33] leading-relaxed">{active.whatItDoes}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-[11px] font-semibold text-[#475569] uppercase tracking-wider">Why it matters</p>
                      <p className="text-xs text-[#252B33] leading-relaxed">{active.whyItMatters}</p>
                    </div>
                    <div className="space-y-1.5">
                      <p className="text-[11px] font-semibold text-[#475569] uppercase tracking-wider">Things to check</p>
                      <ul className="space-y-1">
                        {active.checkThese.map((c, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-[#252B33]">
                            <ChevronRight className="w-3 h-3 mt-0.5 shrink-0 text-[#1677C8]" />
                            {c}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Simulate action */}
                    <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] space-y-2.5">
                      <p className="text-[11px] font-semibold text-[#475569] uppercase tracking-wider">Run Simulation (Sandbox)</p>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          value={target}
                          onChange={(e) => setTarget(e.target.value)}
                          placeholder="Target (username, host, or IP)"
                          className="flex-1 bg-white border border-[#DDE3EA] rounded-md px-3 py-1.5 text-xs text-[#252B33] font-mono focus:outline-none focus:border-[#1677C8]"
                        />
                        <button
                          onClick={handleSimulate}
                          disabled={loading || !target.trim()}
                          className="px-3 py-1.5 rounded-md font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white transition disabled:opacity-50 shrink-0"
                        >
                          {loading ? 'Running…' : 'Simulate'}
                        </button>
                      </div>

                      {/* Console output */}
                      {consoleLog.length > 0 && (
                        <div className="rounded-lg bg-[#1B232D] p-3 font-mono text-[11px] space-y-1 max-h-24 overflow-y-auto">
                          {consoleLog.map((log, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <span className="text-[#475569] shrink-0">[{log.timestamp}]</span>
                              <span className={
                                log.type === 'success' ? 'text-[#4ADE80]' :
                                log.type === 'error' ? 'text-[#F87171]' : 'text-[#CBD5E1]'
                              }>{log.text}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Outcome selection */}
                    <div className="space-y-2">
                      <p className="text-[11px] font-semibold text-[#475569] uppercase tracking-wider">What did you find?</p>
                      <div className="flex gap-2">
                        {[
                          { id: 'suspicious', label: 'Suspicious', icon: AlertTriangle, color: '#C53030', bg: '#FEF2F2' },
                          { id: 'benign', label: 'Likely Benign', icon: ThumbsUp, color: '#16A34A', bg: '#ECFDF5' },
                          { id: 'inconclusive', label: 'Inconclusive', icon: HelpCircle, color: '#D69E2E', bg: '#FEFCBF' },
                        ].map(opt => {
                          const Icon = opt.icon;
                          const isActive = outcome === opt.id;
                          return (
                            <button
                              key={opt.id}
                              onClick={() => setOutcome(opt.id)}
                              className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg border text-[11px] font-semibold transition"
                              style={{
                                backgroundColor: isActive ? opt.bg : '#F8FAFC',
                                borderColor: isActive ? opt.color : '#DDE3EA',
                                color: isActive ? opt.color : '#657180',
                              }}
                            >
                              <Icon className="w-3.5 h-3.5" />
                              {opt.label}
                            </button>
                          );
                        })}
                      </div>
                      {outcome === 'suspicious' && (
                        <p className="text-[11px] text-[#C53030] bg-[#FEF2F2] rounded-lg p-2.5 border border-red-200">
                          <strong>Next:</strong> Open the Alert Detail panel to gather more evidence, then save your findings to a Case for escalation.
                        </p>
                      )}
                      {outcome === 'benign' && (
                        <p className="text-[11px] text-[#16A34A] bg-[#ECFDF5] rounded-lg p-2.5 border border-emerald-200">
                          <strong>Good.</strong> Document the reason it is benign in your Case notes so future analysts do not re-investigate the same event.
                        </p>
                      )}
                      {outcome === 'inconclusive' && (
                        <p className="text-[11px] text-[#B7791F] bg-[#FEFCBF] rounded-lg p-2.5 border border-yellow-300">
                          <strong>Keep investigating.</strong> Try a different step above or check additional log sources. Document what you have found so far.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {!active && (
                <div className="text-center py-8 text-[#94A3B8] text-xs italic">
                  Select an investigation step above to see guidance and run a simulation.
                </div>
              )}
            </>
          ) : (
            /* Audit log tab */
            <div className="space-y-2">
              {history.length === 0 ? (
                <div className="text-center py-8 text-[#657180] text-xs">
                  No simulation steps recorded yet.
                </div>
              ) : (
                history.map((h) => (
                  <div key={h.id} className="p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] text-xs space-y-1">
                    <div className="flex items-center justify-between font-mono text-[10px]">
                      <span className="text-[#1677C8] font-bold">{h.action_name} &rarr; {h.target}</span>
                      <span className="text-[#657180]">{h.timestamp?.substring(11, 19)}</span>
                    </div>
                    <p className="text-[#252B33] font-mono text-[11px]">{h.simulation_result}</p>
                    <div className="text-[10px] text-[#657180] font-mono">
                      Operator: {h.performed_by} &bull; Status: {h.status}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Sandbox disclaimer */}
          <div className="p-2.5 rounded-lg bg-[#EAF3FB] border border-[#BFDBFE] text-[10px] text-[#475569] flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-[#1677C8] shrink-0" />
            <span>
              <strong className="text-[#1677C8]">Simulation only.</strong> No real accounts are locked, no machines are isolated, and no network changes are made. All actions are recorded for demonstration purposes.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
