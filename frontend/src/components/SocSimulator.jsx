import React, { useState, useEffect } from 'react';
import { 
  Terminal, Shield, Play, Lock, Cpu, Globe, 
  RotateCcw, History, CheckCircle2, AlertTriangle, 
  HelpCircle, Server, User, ArrowRight, Zap, Info, ShieldCheck
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function SocSimulator({ defaultTarget = 'm.vasquez' }) {
  const [activeTab, setActiveTab] = useState('actions'); // 'actions' | 'scenarios' | 'history'
  const [selectedAction, setSelectedAction] = useState('revoke_tokens');
  const [target, setTarget] = useState(defaultTarget);
  const [analystName, setAnalystName] = useState('SOC Tier 2 Analyst');
  const [loading, setLoading] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [consoleLogs, setConsoleLogs] = useState([
    `[SYSTEM] SOC Defensive Simulator v2.4 initialized.`,
    `[INFO] Sandbox environment active. Real infrastructure changes disabled.`,
    `[READY] Select a containment action and target asset to simulate response.`
  ]);

  const SIMULATION_ACTIONS = [
    {
      id: 'revoke_tokens',
      title: 'Revoke Authentication Tokens',
      category: 'Identity Containment',
      icon: Lock,
      color: '#10B981',
      bg: '#ECFDF5',
      defaultTarget: 'm.vasquez',
      description: 'Simulates invalidating all active Okta/OAuth JWT tokens and SSO sessions for the compromised identity.',
      impact: 'Forces the attacker out of established cloud and web sessions immediately.',
      checks: [
        'Confirm if anomalous concurrent sessions occurred from external IPs',
        'Verify if multi-factor authentication was bypassed or push-fatigued',
        'Inspect IdP session logs for token refresh activity'
      ]
    },
    {
      id: 'quarantine_host',
      title: 'Isolate & Quarantine Host',
      category: 'Endpoint Isolation',
      icon: Cpu,
      color: '#6366F1',
      bg: '#EEF2FF',
      defaultTarget: 'WORKSTATION-04',
      description: 'Dispatches network isolation instruction to simulated EDR agent, severing all network routes except SOC triage VLAN.',
      impact: 'Arrests lateral movement propagation (SMB, RDP, SSH) across internal network segments.',
      checks: [
        'Check for active lateral connections to database or domain controllers',
        'Inspect process trees for PowerShell or Sysmon anomaly spikes',
        'Verify host endpoint patch level and local admin account access'
      ]
    },
    {
      id: 'force_password_reset',
      title: 'Force Enterprise Password Reset',
      category: 'Identity Containment',
      icon: Shield,
      color: '#F59E0B',
      bg: '#FFFBEB',
      defaultTarget: 'm.vasquez',
      description: 'Sets UserMustChangePassword flag in simulated Active Directory and invalidates Kerberos TGT tickets.',
      impact: 'Prevents credential re-use across on-premises domain resources.',
      checks: [
        'Audit domain controller Event ID 4723 and 4724 logs',
        'Contact employee through verified out-of-band communication',
        'Ensure password change is completed on compliant corporate asset'
      ]
    },
    {
      id: 'block_ip',
      title: 'Perimeter Firewall Null-Route IP',
      category: 'Network Perimeter',
      icon: Globe,
      color: '#EF4444',
      bg: '#FEF2F2',
      defaultTarget: '203.0.113.88',
      description: 'Injects simulated border gateway rule dropping all incoming and outbound packets associated with threat IP.',
      impact: 'Terminates active Command & Control (C2) beaconing and data exfiltration pipelines.',
      checks: [
        'Cross-reference IP reputation on AbuseIPDB, VirusTotal, and AlienVault',
        'Search firewall egress telemetry for total bytes transmitted',
        'Check if internal assets resolved related malicious DNS records'
      ]
    },
    {
      id: 'snapshot_memory',
      title: 'Capture Volatile Memory Dump',
      category: 'Forensic Preservation',
      icon: Server,
      color: '#8B5CF6',
      bg: '#F5F3FF',
      defaultTarget: 'PROD-DB01',
      description: 'Preserves non-volatile RAM state into sandboxed storage volume for deep offline malware inspection.',
      impact: 'Preserves in-memory payloads, unencrypted credentials, and injection threads before reboot.',
      checks: [
        'Ensure target server has adequate disk headroom for RAM image',
        'Verify hash signature of memory dump upon acquisition',
        'Check for injected DLLs and unmapped code segments in memory'
      ]
    }
  ];

  // Fetch simulation audit history
  const fetchHistory = async () => {
    try {
      const res = await apiClient.getPlaybookHistory();
      setHistory(res.history || []);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleActionSelect = (act) => {
    setSelectedAction(act.id);
    setTarget(act.defaultTarget);
  };

  const handleExecuteSimulation = async () => {
    if (!target) return;
    setLoading(true);
    const actionObj = SIMULATION_ACTIONS.find(a => a.id === selectedAction);

    const timestamp = new Date().toLocaleTimeString();
    setConsoleLogs(prev => [
      ...prev,
      `[${timestamp}] DISPATCHING: Simulated action "${actionObj?.title}" against "${target}"...`
    ]);

    try {
      const res = await apiClient.simulatePlaybook({
        playbook_name: actionObj?.title || selectedAction,
        action_name: selectedAction,
        target: target,
        parameters: { analyst: analystName, simulated_timestamp: new Date().toISOString() },
        analyst: analystName
      });

      setExecutionResult(res);
      setConsoleLogs(prev => [
        ...prev,
        `[${timestamp}] SUCCESS: ${res.simulation_result}`,
        `[${timestamp}] NOTICE: ${res.ethical_notice}`
      ]);
      fetchHistory();
    } catch (err) {
      setConsoleLogs(prev => [
        ...prev,
        `[${timestamp}] ERROR: Simulation failed - ${err.message}`
      ]);
    } finally {
      setLoading(false);
    }
  };

  const currentAction = SIMULATION_ACTIONS.find(a => a.id === selectedAction) || SIMULATION_ACTIONS[0];

  return (
    <div className="space-y-5 text-[#0F172A]">
      {/* Header Banner */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-card flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0] uppercase font-semibold">
              Isolated Simulation Sandbox
            </span>
            <span className="text-xs text-[#64748B]">
              Defensive Incident Containment &amp; Playbooks
            </span>
          </div>
          <h1 className="text-xl font-bold text-[#0F172A] tracking-tight">
            TraceX SOC Incident Simulator
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5 max-w-2xl leading-relaxed">
            Safely test incident response containment playbooks against synthetic assets. All operations run in an isolated test harness without modifying live production infrastructure or contaminating uploaded CSV log investigations.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1.5 p-1 bg-[#F1F5F9] rounded-lg border border-[#E2E8F0] text-xs">
          <button
            onClick={() => setActiveTab('actions')}
            className={`px-3 py-1.5 rounded-md font-semibold transition ${
              activeTab === 'actions' 
                ? 'bg-white text-[#0F172A] shadow-subtle' 
                : 'text-[#64748B] hover:text-[#0F172A]'
            }`}
          >
            Playbook Actions
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-3 py-1.5 rounded-md font-semibold transition ${
              activeTab === 'history' 
                ? 'bg-white text-[#0F172A] shadow-subtle' 
                : 'text-[#64748B] hover:text-[#0F172A]'
            }`}
          >
            Audit History ({history.length})
          </button>
        </div>
      </div>

      {activeTab === 'actions' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Action Selector Column */}
          <div className="space-y-2.5">
            <h2 className="text-xs font-mono uppercase tracking-wider text-[#64748B] font-semibold px-1">
              Select Defensive Playbook
            </h2>
            {SIMULATION_ACTIONS.map((action) => {
              const Icon = action.icon;
              const isSelected = selectedAction === action.id;
              return (
                <div
                  key={action.id}
                  onClick={() => handleActionSelect(action)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer shadow-subtle ${
                    isSelected
                      ? 'bg-white border-[#10B981] ring-2 ring-[#10B981]/20'
                      : 'bg-white hover:bg-[#F8FAFC] border-[#E2E8F0]'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <div 
                      className="p-2 rounded-lg shrink-0"
                      style={{ backgroundColor: action.bg, color: action.color }}
                    >
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs text-[#0F172A] truncate">
                          {action.title}
                        </span>
                        {isSelected && (
                          <span className="w-2 h-2 rounded-full bg-[#10B981]" />
                        )}
                      </div>
                      <span className="text-[10px] text-[#64748B] font-mono block">
                        {action.category}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Action Detail & Target Configuration Column */}
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-card space-y-4">
              <div className="flex items-start justify-between pb-3 border-b border-[#E2E8F0]">
                <div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#F1F5F9] text-[#64748B] uppercase font-semibold">
                    {currentAction.category}
                  </span>
                  <h3 className="text-base font-bold text-[#0F172A] mt-1">
                    {currentAction.title}
                  </h3>
                </div>
                <div 
                  className="p-2 rounded-lg"
                  style={{ backgroundColor: currentAction.bg, color: currentAction.color }}
                >
                  <currentAction.icon className="w-5 h-5" />
                </div>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <strong className="text-[#0F172A] block mb-0.5">Simulated Operation:</strong>
                  <p className="text-[#64748B] leading-relaxed">{currentAction.description}</p>
                </div>
                <div>
                  <strong className="text-[#0F172A] block mb-0.5">Defensive Containment Value:</strong>
                  <p className="text-[#059669] font-medium leading-relaxed">{currentAction.impact}</p>
                </div>

                <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                  <strong className="text-[#0F172A] block text-[11px] mb-1.5 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
                    Analyst Pre-flight Verification Checklist:
                  </strong>
                  <ul className="space-y-1 text-[#64748B] text-[11px]">
                    {currentAction.checks.map((c, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-[#10B981] font-bold">•</span>
                        <span>{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Target Configuration Input */}
                <div className="pt-2 border-t border-[#E2E8F0] grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-semibold text-[#0F172A] mb-1">
                      Simulated Target Asset / Entity:
                    </label>
                    <input
                      type="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="e.g. m.vasquez, WORKSTATION-04, 203.0.113.88"
                      className="w-full bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg px-3 py-2 text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#10B981] focus:bg-white"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-semibold text-[#0F172A] mb-1">
                      Operating Analyst:
                    </label>
                    <input
                      type="text"
                      value={analystName}
                      onChange={(e) => setAnalystName(e.target.value)}
                      className="w-full bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg px-3 py-2 text-xs text-[#0F172A] focus:outline-none focus:border-[#10B981] focus:bg-white"
                    />
                  </div>
                </div>

                {/* Dispatch Button */}
                <div className="pt-2 flex items-center justify-between">
                  <div className="text-[11px] text-[#64748B] flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-[#F59E0B]" />
                    <span>Dry-run simulation: No network disruption committed.</span>
                  </div>
                  <button
                    onClick={handleExecuteSimulation}
                    disabled={loading || !target}
                    className="flex items-center gap-2 px-5 py-2 rounded-lg font-semibold text-xs bg-[#10B981] hover:bg-[#059669] text-white shadow-sm transition disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{loading ? 'Simulating Dispatch...' : 'Execute Simulation'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Simulated Live Console Log */}
            <div className="bg-[#0F172A] border border-[#1E293B] rounded-xl overflow-hidden shadow-card">
              <div className="px-4 py-2.5 bg-[#1E293B] border-b border-[#334155] flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
                  <Terminal className="w-3.5 h-3.5 text-[#10B981]" />
                  <span>Defensive Simulator Execution Console</span>
                </div>
                <button
                  onClick={() => setConsoleLogs([`[CLEARED] Console buffer reset at ${new Date().toLocaleTimeString()}`])}
                  className="text-[10px] text-slate-400 hover:text-white transition font-mono"
                >
                  Clear Buffer
                </button>
              </div>
              <div className="p-3.5 font-mono text-xs text-slate-200 max-h-48 overflow-y-auto space-y-1 selection:bg-[#10B981] selection:text-black">
                {consoleLogs.map((log, i) => (
                  <div key={i} className={`leading-relaxed ${
                    log.includes('SUCCESS') ? 'text-emerald-400 font-semibold' :
                    log.includes('DISPATCHING') ? 'text-amber-300' :
                    log.includes('ERROR') ? 'text-red-400' :
                    'text-slate-300'
                  }`}>
                    {log}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Audit History Tab */
        <div className="bg-white border border-[#E2E8F0] rounded-xl overflow-hidden shadow-card">
          <div className="p-4 border-b border-[#E2E8F0] flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#0F172A]">Simulated Playbook Execution Records</h3>
              <p className="text-xs text-[#64748B]">Audit log of defensive simulations recorded in the database</p>
            </div>
            <button
              onClick={fetchHistory}
              className="text-xs text-[#10B981] hover:underline font-medium"
            >
              Refresh Audit
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-[#64748B] font-mono text-[11px]">
                  <th className="py-2.5 px-4 font-semibold">Exec ID</th>
                  <th className="py-2.5 px-4 font-semibold">Playbook Action</th>
                  <th className="py-2.5 px-4 font-semibold">Target Asset</th>
                  <th className="py-2.5 px-4 font-semibold">Timestamp</th>
                  <th className="py-2.5 px-4 font-semibold">Status</th>
                  <th className="py-2.5 px-4 font-semibold">Analyst</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0] text-[#0F172A]">
                {history.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[#64748B] text-xs">
                      No playbook simulation executions recorded yet. Execute an action to record an audit entry.
                    </td>
                  </tr>
                ) : (
                  history.map((h) => (
                    <tr key={h.id} className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="py-2.5 px-4 font-mono text-[11px] text-[#64748B]">
                        {h.id}
                      </td>
                      <td className="py-2.5 px-4 font-semibold text-[#0F172A]">
                        {h.playbook_name || h.action_name}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[#059669] font-medium">
                        {h.target}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[#64748B] text-[11px]">
                        {h.timestamp ? h.timestamp.substring(11, 19) : '-'}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]">
                          {h.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#64748B]">
                        {h.performed_by}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
