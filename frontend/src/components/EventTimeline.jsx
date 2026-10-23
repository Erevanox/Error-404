import React, { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import {
  Clock, ShieldAlert, ExternalLink, ChevronLeft, ChevronRight,
  X, Info, User, Monitor, Globe, Activity, Search, Filter,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Eye,
  Layers, Database, ArrowRight, ArrowLeft, GitCommit, Copy, Check
} from 'lucide-react';

// ─── Constants ────────────────────────────────────────────────────────────────
const CLUSTER_THRESHOLD_MS = 45_000; // events within 45 s share a marker
const EDGE_GUARD = 0.04;

// ─── Plain-language event labels ─────────────────────────────────────────────
const FRIENDLY_LABEL = {
  brute_force_attempt:          'Repeated login failures',
  brute_force_success:          'Login after repeated failures',
  credential_stuffing:          'Password-spray attack pattern',
  login_success:                'Successful login',
  login_failure:                'Failed login attempt',
  auth_failure:                 'Failed login attempt',
  failed_login:                 'Failed login attempt',
  successful_login:             'Successful login',
  login_off_hours:              'Unusual login time',
  privilege_escalation:         'Permission change detected',
  privilege_change:             'Privileged execution / sudo invocation',
  lateral_movement:             'Unexpected system access',
  lateral_connection:           'Internal remote service connection',
  process_execution:            'Interactive process launched',
  suspicious_process:           'Unusual process started',
  data_exfiltration:            'Large data transfer',
  data_transfer:                'High-volume outbound data transfer',
  large_data_transfer:          'Large data transfer',
  port_scan:                    'Network scan detected',
  suspicious_outbound:          'Unusual outbound connection',
  firewall_block:               'Connection blocked by firewall',
  service_restart:              'System service restarted',
  config_change:                'System configuration changed',
  account_created:              'New account created',
  account_locked:               'Account locked out',
};

function friendlyLabel(event_type) {
  if (!event_type) return 'Security event';
  const key = event_type.toLowerCase().replace(/\s+/g, '_');
  return FRIENDLY_LABEL[key] || event_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// "Why should I care?" messages per event_type ─────────────────────────────
const IMPACT_NOTE = {
  brute_force_attempt:    'Multiple rapid login failures may indicate someone trying to guess a password. If successful, they could access private data or systems.',
  failed_login:           'Multiple rapid login failures may indicate someone trying to guess a password. If successful, they could access private data or systems.',
  brute_force_success:    'A successful login following many failures is a strong indicator of a compromised password. This account may need immediate attention.',
  successful_login:       'A successful login following multiple failures represents an essential breach milestone, indicating unauthorized access.',
  login_off_hours:        'Logins at unusual times (e.g., 3 AM) can indicate unauthorized access, especially if the user does not normally work those hours.',
  privilege_escalation:   'Gaining elevated permissions allows an attacker to access more systems and data — this is a key step in most serious breaches.',
  privilege_change:       'Executing commands as root or administrator allows full control over the local system and sensitive databases.',
  lateral_movement:       'Accessing other systems from an already-compromised account can allow an attacker to spread further through the network.',
  lateral_connection:     'Connecting to internal file shares or database ports (e.g. SMB/SSH) from a workstation is typical of internal pivot activity.',
  process_execution:      'Spawning interactive shells (such as PowerShell or CMD) can indicate adversary command execution or reconnaissance.',
  data_exfiltration:      'Unusually large data transfers out of the network could mean sensitive files are being copied and sent elsewhere.',
  data_transfer:          'Unusually high data transfer volume to external IP addresses warrants immediate verification against data egress policies.',
  suspicious_process:     'Programs that start unexpectedly may be malware attempting to hide or spread.',
  port_scan:              'Scanning for open ports is often a reconnaissance step before a targeted attack.',
};

function impactNote(event_type) {
  const key = (event_type || '').toLowerCase().replace(/\s+/g, '_');
  return IMPACT_NOTE[key] || 'This activity was flagged as unusual based on detection rules. Investigate to determine whether it was authorized.';
}

// "What to check next?" ────────────────────────────────────────────────────
const NEXT_STEP = {
  brute_force_attempt:    'Review the source IP. Check whether the targeted account is still active and whether any login eventually succeeded.',
  failed_login:           'Review the source IP. Check whether the targeted account is still active and whether any login eventually succeeded.',
  brute_force_success:    'Verify with the account owner whether this login was expected. Consider resetting the password and reviewing recent activity.',
  successful_login:       'Verify with the account owner whether this login was expected. Check for any new files accessed or commands run after this login.',
  login_off_hours:        'Confirm with the user whether they logged in at this time. Check for any new files accessed or commands run after this login.',
  privilege_escalation:   'Confirm whether this permission change was requested and approved. Review what the account did with the elevated access.',
  privilege_change:       'Inspect the command arguments in sudo audit logs and verify whether the user was authorized to run administrative dumps.',
  lateral_movement:       'Identify all systems this account accessed. Determine whether the access was part of normal work.',
  lateral_connection:     'Check the destination server logs to verify whether files or database tables were read or modified.',
  process_execution:      'Inspect parent process and command line parameters to identify who launched the script and what arguments were passed.',
  data_exfiltration:      'Identify what data was transferred and to where. Confirm whether the destination endpoint is a verified corporate asset.',
  data_transfer:          'Perform IP reputation checks on destination address and determine what files were included in the outbound transfer.',
  suspicious_process:     'Identify the process name and who launched it. Check whether it is a known tool or an unexpected executable.',
  port_scan:              'Identify the scanning source and block it if unknown. Determine whether any open ports should be closed.',
};

function nextStep(event_type) {
  const key = (event_type || '').toLowerCase().replace(/\s+/g, '_');
  return NEXT_STEP[key] || 'Cross-reference this event with related logs to determine whether the activity was authorized or part of a larger pattern.';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function parseTs(ts) {
  if (!ts) return null;
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

function fmtFull(ts) {
  const d = parseTs(ts);
  if (!d) return ts ?? '—';
  return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
}

function fmtShort(ts) {
  const d = parseTs(ts);
  if (!d) return '??:??:??';
  return d.toISOString().substring(11, 19);
}

function fmtDate(ts) {
  const d = parseTs(ts);
  if (!d) return '';
  return d.toISOString().substring(0, 10);
}

function calcPosition(ts, startMs, endMs) {
  const span = endMs - startMs;
  if (span <= 0) return 0.5;
  return Math.max(EDGE_GUARD, Math.min(1 - EDGE_GUARD, (ts - startMs) / span));
}

// ─── 3-tier severity indicators ──────────────────────────────────────────────
function getSevTier(score) {
  const s = score ?? 0;
  if (s >= 7.0) return 'HIGH';
  if (s >= 4.5) return 'MEDIUM';
  return 'LOW';
}

const TIER_STYLE = {
  HIGH: {
    border:      'border-[#DC2626]',
    borderDark:  '#B91C1C',
    ring:        'ring-[#DC2626]',
    badge:       'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]',
    text:        'text-[#C53030]',
    bg:          'bg-[#FEF2F2]',
    label:       'High Risk',
    icon:        '🔴',
    colorHex:    '#DC2626',
    diamondColor:'#EF4444'
  },
  MEDIUM: {
    border:      'border-[#D97706]',
    borderDark:  '#B45309',
    ring:        'ring-[#D97706]',
    badge:       'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]',
    text:        'text-[#DD6B20]',
    bg:          'bg-[#FFFAF0]',
    label:       'Needs Attention',
    icon:        '🟠',
    colorHex:    '#D97706',
    diamondColor:'#F59E0B'
  },
  LOW: {
    border:      'border-[#2563EB]',
    borderDark:  '#1D4ED8',
    ring:        'ring-[#2563EB]',
    badge:       'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]',
    text:        'text-[#1677C8]',
    bg:          'bg-[#F8FAFC]',
    label:       'Informational',
    icon:        '🔵',
    colorHex:    '#2563EB',
    diamondColor:'#3B82F6'
  },
};

function getTierStyle(score) {
  return TIER_STYLE[getSevTier(score)];
}

// ─── Distinct Category Styles (Authentication, System, Network) ───────────────
const CATEGORY_STYLE = {
  AUTHENTICATION: {
    label: 'Authentication',
    fillColor: '#8B5CF6', // Purple
    badge: 'bg-[#F5F3FF] text-[#8B5CF6] border-[#C4B5FD]',
    icon: '🟣',
    glyph: 'AUTH'
  },
  SYSTEM: {
    label: 'System',
    fillColor: '#0284C7', // Sky Blue
    badge: 'bg-[#F0F9FF] text-[#0284C7] border-[#BAE6FD]',
    icon: '🔵',
    glyph: 'SYS'
  },
  NETWORK: {
    label: 'Network',
    fillColor: '#059669', // Emerald
    badge: 'bg-[#ECFDF5] text-[#059669] border-[#A7F3D0]',
    icon: '🟢',
    glyph: 'NET'
  }
};

function getCategoryStyle(cat) {
  const c = (cat || '').toUpperCase();
  if (c.includes('AUTH')) return CATEGORY_STYLE.AUTHENTICATION;
  if (c.includes('SYS')) return CATEGORY_STYLE.SYSTEM;
  if (c.includes('NET')) return CATEGORY_STYLE.NETWORK;
  return CATEGORY_STYLE.SYSTEM;
}

// ─── Legend Items ────────────────────────────────────────────────────────────
function LegendItem({ dotColor, label, isDiamond = false }) {
  return (
    <span className="flex items-center gap-1.5 text-xs text-[#475569]">
      {isDiamond ? (
        <span
          className="w-2.5 h-2.5 rotate-45 shrink-0 border border-white shadow-xs"
          style={{ backgroundColor: dotColor }}
          aria-hidden="true"
        />
      ) : (
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0 border border-white ring-1 ring-[#CBD5E1]"
          style={{ backgroundColor: dotColor }}
          aria-hidden="true"
        />
      )}
      <span>{label}</span>
    </span>
  );
}

function FieldRow({ label, value, mono = true }) {
  const display = value != null && value !== '' ? value : 'Not available';
  const isMissing = display === 'Not available';
  return (
    <div className="flex gap-2 text-xs leading-relaxed">
      <span className="text-[#657180] w-28 shrink-0 font-medium">{label}</span>
      <span className={`${mono ? 'font-mono' : ''} ${isMissing ? 'text-[#94A3B8] italic' : 'text-[#252B33]'} break-all`}>
        {display}
      </span>
    </div>
  );
}

// ─── Detail Panel (Phase 3B: Selected Event Investigation Panel) ─────────────
function SelectedEventPanel({
  cluster,
  clusterIndex,
  totalClusters,
  allFilteredEvents,
  onPrev,
  onNext,
  onClose,
  onInspectEvent,
  alerts
}) {
  const [innerIdx, setInnerIdx] = useState(0);
  const [showTech, setShowTech] = useState(false);
  const [copiedRawLog, setCopiedRawLog] = useState(false);

  useEffect(() => {
    setInnerIdx(0);
    setShowTech(false);
  }, [clusterIndex]);

  const event = cluster?.events?.[innerIdx];
  if (!event) return null;

  const tier = getTierStyle(event.severity_score);
  const catStyle = getCategoryStyle(event.category);
  const clusterSize = cluster.events.length;
  const label = friendlyLabel(event.event_type);
  const impact = impactNote(event.event_type);
  const next = nextStep(event.event_type);
  const explanation = event.explanation || event.what_happened || event.description || null;
  const corrRule = event.correlation_rule || event.rule_name || null;

  // Identify matching alert
  const relatedAlert = alerts?.find(a => 
    a.supporting_event_ids?.includes(event.id) ||
    a.primary_user === event.user ||
    a.primary_ip === event.source_ip
  );

  // Find chronological predecessor and successor events across the filtered timeline
  const currentGlobalIndex = allFilteredEvents.findIndex(e => e.id === event.id);
  const prevEvent = currentGlobalIndex > 0 ? allFilteredEvents[currentGlobalIndex - 1] : null;
  const nextEvent = currentGlobalIndex >= 0 && currentGlobalIndex < allFilteredEvents.length - 1 
    ? allFilteredEvents[currentGlobalIndex + 1] 
    : null;

  const calcDelta = (t1, t2) => {
    if (!t1 || !t2) return null;
    const diff = Math.round((new Date(t2).getTime() - new Date(t1).getTime()) / 1000);
    if (Math.abs(diff) < 60) return `${diff > 0 ? '+' : ''}${diff}s`;
    const mins = Math.round(diff / 60);
    return `${mins > 0 ? '+' : ''}${mins}m`;
  };

  const handleCopyRaw = () => {
    if (!event.raw_log) return;
    navigator.clipboard.writeText(event.raw_log);
    setCopiedRawLog(true);
    setTimeout(() => setCopiedRawLog(false), 2000);
  };

  return (
    <div
      className={`mt-6 rounded-xl border ${tier.border} ${tier.bg} overflow-hidden shadow-card transition-all`}
      role="region"
      aria-label="Selected event investigation panel"
    >
      {/* Panel header bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#DDE3EA] bg-white">
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Category Badge */}
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${catStyle.badge}`}>
            {catStyle.icon} {catStyle.label}
          </span>
          {/* Severity Badge */}
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${tier.badge}`}>
            {tier.icon} {tier.label} ({event.severity_score ? event.severity_score.toFixed(1) : '1.0'}/10)
          </span>
          <span className="text-xs font-mono font-bold text-[#475569] bg-[#F1F5F9] px-2 py-0.5 rounded border border-[#E2E8F0]">
            {event.id}
          </span>
          <span className="text-sm font-semibold text-[#0F172A]">{label}</span>
          {clusterSize > 1 && (
            <span className="text-[10px] text-[#657180] border border-[#CBD5E1] bg-[#F8FAFC] rounded px-1.5 py-0.5 font-mono">
              Event {innerIdx + 1} of {clusterSize} clustered at this second
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {/* Within-cluster navigation */}
          {clusterSize > 1 && (
            <div className="flex items-center gap-1 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-0.5 mr-1">
              <button 
                onClick={() => setInnerIdx(i => Math.max(0, i - 1))} 
                disabled={innerIdx === 0}
                className="p-1 rounded text-[#64748B] hover:text-[#0F172A] disabled:opacity-25 transition" 
                aria-label="Previous event in group"
                title="Previous event in cluster"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="font-mono text-[10px] px-1 text-[#64748B]">
                {innerIdx + 1}/{clusterSize}
              </span>
              <button 
                onClick={() => setInnerIdx(i => Math.min(clusterSize - 1, i + 1))} 
                disabled={innerIdx === clusterSize - 1}
                className="p-1 rounded text-[#64748B] hover:text-[#0F172A] disabled:opacity-25 transition" 
                aria-label="Next event in group"
                title="Next event in cluster"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Cross-cluster timeline marker navigation */}
          <button 
            onClick={onPrev} 
            disabled={clusterIndex === 0}
            className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0284C7] hover:bg-[#F1F5F9] disabled:opacity-25 transition border border-[#E2E8F0]" 
            aria-label="Previous timeline marker"
            title="Previous event marker (←)"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-[11px] text-[#64748B] px-1 select-none font-semibold">
            {clusterIndex + 1} / {totalClusters}
          </span>
          <button 
            onClick={onNext} 
            disabled={clusterIndex === totalClusters - 1}
            className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0284C7] hover:bg-[#F1F5F9] disabled:opacity-25 transition border border-[#E2E8F0]" 
            aria-label="Next timeline marker"
            title="Next event marker (→)"
          >
            <ChevronRight className="w-4 h-4" />
          </button>

          <div className="w-px h-5 bg-[#DDE3EA] mx-1" />
          <button 
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#64748B] hover:text-[#DC2626] hover:bg-[#FEE2E2] transition border border-[#E2E8F0]" 
            aria-label="Close investigation panel"
            title="Close panel (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Investigation Body */}
      <div className="p-5 space-y-4">
        {/* Top Summary Banner */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="bg-white p-3 rounded-lg border border-[#E2E8F0] space-y-1">
            <span className="text-[10px] text-[#64748B] uppercase font-bold tracking-wider block">Observed Timestamp</span>
            <div className="font-mono text-xs font-bold text-[#0F172A] flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[#0284C7]" />
              <span>{fmtFull(event.timestamp)}</span>
            </div>
          </div>

          <div className="bg-white p-3 rounded-lg border border-[#E2E8F0] space-y-1">
            <span className="text-[10px] text-[#64748B] uppercase font-bold tracking-wider block">Target Identity / Asset</span>
            <div className="font-mono text-xs text-[#0F172A] flex items-center gap-2">
              <User className="w-3.5 h-3.5 text-[#8B5CF6]" />
              <strong className="truncate">{event.user || 'None recorded'}</strong>
              <span className="text-[#94A3B8]">@</span>
              <span className="truncate">{event.host || event.source_ip || 'Network'}</span>
            </div>
          </div>

          <div className="bg-white p-3 rounded-lg border border-[#E2E8F0] space-y-1">
            <span className="text-[10px] text-[#64748B] uppercase font-bold tracking-wider block">Correlated Case / Alert</span>
            <div className="text-xs font-semibold text-[#0F172A] flex items-center gap-1.5 truncate">
              {relatedAlert ? (
                <>
                  <span className="font-mono text-[10px] text-[#059669] bg-[#ECFDF5] px-1.5 py-0.5 rounded border border-[#A7F3D0]">
                    {relatedAlert.id}
                  </span>
                  <span className="truncate text-[#0F172A]">{relatedAlert.title}</span>
                </>
              ) : (
                <span className="text-[#94A3B8] italic">Uncorrelated telemetry record</span>
              )}
            </div>
          </div>
        </div>

        {/* Structured Forensic Assessment Questions */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Left Column: What happened & Why flagged */}
          <div className="space-y-3 bg-white p-4 rounded-xl border border-[#E2E8F0]">
            <div>
              <p className={`text-[10px] font-bold uppercase tracking-wider mb-1 ${tier.text}`}>
                🔍 Forensic Analysis: What occurred?
              </p>
              <p className="text-xs text-[#1E293B] leading-relaxed">
                {explanation || `The platform recorded an event of type '${label}' for account '${event.user || 'unspecified'}' originating from '${event.source_ip || event.host || 'unknown endpoint'}'. Action status: ${event.action || event.status || 'observed'}.`}
              </p>
            </div>

            <div className="border-t border-[#F1F5F9] pt-2.5">
              <p className={`text-[10px] font-bold uppercase tracking-wider mb-1 ${tier.text}`}>
                ⚠️ Why was this flagged or correlated?
              </p>
              <p className="text-xs text-[#475569] leading-relaxed">
                {corrRule
                  ? `Triggered SIEM detection rule "${corrRule.replace(/_/g, ' ')}" based on temporal proximity and suspicious parameter threshold.`
                  : `Assigned a severity rating of ${event.severity_score ? event.severity_score.toFixed(1) : '1.0'}/10.0 due to action '${event.action || event.status || 'observed'}' within the ${event.category || 'security'} telemetry layer.`}
              </p>
            </div>
          </div>

          {/* Right Column: Security Impact & Recommended Next Action */}
          <div className="space-y-3 bg-white p-4 rounded-xl border border-[#E2E8F0]">
            <div>
              <p className={`text-[10px] font-bold uppercase tracking-wider mb-1 ${tier.text}`}>
                ❗ Security Impact &amp; Breach Significance
              </p>
              <p className="text-xs text-[#475569] leading-relaxed">{impact}</p>
            </div>

            <div className="border-t border-[#F1F5F9] pt-2.5">
              <p className={`text-[10px] font-bold uppercase tracking-wider mb-1 ${tier.text}`}>
                ✅ Recommended Analyst Investigation Steps
              </p>
              <p className="text-xs text-[#475569] leading-relaxed">{next}</p>
            </div>
          </div>
        </div>

        {/* Temporal Sequence Context (Events Before & After in Chronological Order) */}
        <div className="bg-white p-3.5 rounded-xl border border-[#E2E8F0]">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#64748B] block mb-2">
            Chronological Sequence Context (Preceding &amp; Subsequent Activity)
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
            {/* Preceding Event */}
            <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-1">
              <span className="text-[10px] text-[#64748B] font-semibold flex items-center gap-1">
                <ArrowLeft className="w-3 h-3 text-[#94A3B8]" />
                <span>Preceding Event</span>
                {prevEvent && (
                  <span className="font-mono text-[9px] text-[#059669] bg-white px-1 rounded border border-[#CBD5E1] ml-auto">
                    {calcDelta(prevEvent.timestamp, event.timestamp)}
                  </span>
                )}
              </span>
              {prevEvent ? (
                <div>
                  <p className="font-semibold text-[#0F172A] truncate">{friendlyLabel(prevEvent.event_type)}</p>
                  <p className="font-mono text-[10px] text-[#64748B]">{fmtShort(prevEvent.timestamp)} UTC • {prevEvent.user || prevEvent.source_ip || '-'}</p>
                </div>
              ) : (
                <p className="text-[#94A3B8] italic text-[11px]">First observed event in selected window</p>
              )}
            </div>

            {/* Current Event (Active) */}
            <div className={`p-2.5 rounded-lg border ring-2 ring-inset ${tier.ring} ${tier.bg} space-y-1`}>
              <span className="text-[10px] font-bold flex items-center gap-1" style={{ color: tier.colorHex }}>
                <Clock className="w-3 h-3" />
                <span>CURRENT SELECTED EVENT</span>
              </span>
              <div>
                <p className="font-bold text-[#0F172A] truncate">{label}</p>
                <p className="font-mono text-[10px] text-[#475569]">{fmtShort(event.timestamp)} UTC • {event.id}</p>
              </div>
            </div>

            {/* Subsequent Event */}
            <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-1">
              <span className="text-[10px] text-[#64748B] font-semibold flex items-center gap-1">
                <span>Subsequent Event</span>
                {nextEvent && (
                  <span className="font-mono text-[9px] text-[#0284C7] bg-white px-1 rounded border border-[#CBD5E1] ml-auto">
                    {calcDelta(event.timestamp, nextEvent.timestamp)}
                  </span>
                )}
                <ArrowRight className="w-3 h-3 text-[#94A3B8]" />
              </span>
              {nextEvent ? (
                <div>
                  <p className="font-semibold text-[#0F172A] truncate">{friendlyLabel(nextEvent.event_type)}</p>
                  <p className="font-mono text-[10px] text-[#64748B]">{fmtShort(nextEvent.timestamp)} UTC • {nextEvent.user || nextEvent.source_ip || '-'}</p>
                </div>
              ) : (
                <p className="text-[#94A3B8] italic text-[11px]">Last observed event in selected window</p>
              )}
            </div>
          </div>
        </div>

        {/* Technical Details Accordion */}
        <div className="border-t border-[#DDE3EA] pt-3">
          <button
            type="button"
            onClick={() => setShowTech(v => !v)}
            className="flex items-center gap-2 text-xs text-[#64748B] hover:text-[#0F172A] font-semibold transition"
            aria-expanded={showTech}
          >
            {showTech ? <ChevronUp className="w-4 h-4 text-[#0284C7]" /> : <ChevronDown className="w-4 h-4 text-[#0284C7]" />}
            <span>{showTech ? 'Hide Technical Metadata & Raw Log String' : 'Show Technical Metadata & Raw Log String'}</span>
          </button>

          {showTech && (
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs bg-white p-4 rounded-xl border border-[#DDE3EA]">
              <div className="space-y-1.5">
                <FieldRow label="Event ID" value={event.id} />
                <FieldRow label="Exact ISO UTC" value={event.timestamp} />
                <FieldRow label="Severity score" value={event.severity_score != null ? `${event.severity_score.toFixed(1)} / 10` : null} />
                <FieldRow label="Category" value={event.category} />
                <FieldRow label="Event type" value={event.event_type} />
                <FieldRow label="Action / Status" value={`${event.action || '-'} / ${event.status || '-'}`} />
                <FieldRow label="User identity" value={event.user} />
                <FieldRow label="Source host" value={event.host} />
                <FieldRow label="Source IP:Port" value={event.source_ip ? `${event.source_ip}${event.port ? `:${event.port}` : ''}` : null} />
                <FieldRow label="Destination" value={event.dest_host || event.dest_ip} />
                <FieldRow label="Protocol" value={event.protocol} />
                {event.bytes_out != null && (
                  <FieldRow label="Bytes transfer" value={`${(event.bytes_out / 1024).toFixed(1)} KB`} />
                )}
                <FieldRow label="Correlation rule" value={corrRule} />
              </div>

              <div className="flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-[10px] text-[#64748B] uppercase tracking-wider font-bold">Original Raw Log Entry</p>
                    {event.raw_log && (
                      <button
                        onClick={handleCopyRaw}
                        className="text-[10px] font-mono flex items-center gap-1 text-[#0284C7] hover:underline"
                      >
                        {copiedRawLog ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedRawLog ? 'Copied' : 'Copy log'}</span>
                      </button>
                    )}
                  </div>
                  {event.raw_log ? (
                    <pre className="bg-[#F8FAFC] border border-[#CBD5E1] rounded-lg p-3 text-[10px] font-mono text-[#0F172A] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed max-h-36 shadow-inner">
                      {event.raw_log}
                    </pre>
                  ) : (
                    <p className="text-xs text-[#94A3B8] italic p-3 bg-[#F8FAFC] rounded-lg border border-[#E2E8F0]">
                      No raw log string preserved for this normalized event.
                    </p>
                  )}
                </div>

                <div className="pt-3 flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onInspectEvent(event)}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg text-xs font-semibold bg-[#0284C7] hover:bg-[#0369A1] text-white shadow-subtle transition"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Open in Forensic Evidence Inspector</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function EventTimeline({ events, alerts, selectedAlert, onInspectEvent }) {
  const [selectedAlertId, setSelectedAlertId] = useState(selectedAlert?.id || 'ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selectedClusterIdx, setSelectedClusterIdx] = useState(null);

  // Synchronize with external selectedAlert prop
  useEffect(() => {
    if (selectedAlert?.id) {
      setSelectedAlertId(selectedAlert.id);
    }
  }, [selectedAlert]);

  // Active selected alert object
  const activeAlert = useMemo(() => {
    if (!alerts || selectedAlertId === 'ALL') return null;
    return alerts.find(a => a.id === selectedAlertId) || null;
  }, [alerts, selectedAlertId]);

  // ── 1. Filter events ───────────────────────────────────────────────────────
  const filteredEvents = useMemo(() => {
    if (!events) return [];
    let list = [...events].sort((a, b) => new Date(a.timestamp || 0) - new Date(b.timestamp || 0));

    if (selectedAlertId !== 'ALL' && alerts) {
      const active = alerts.find(a => a.id === selectedAlertId);
      if (active?.supporting_event_ids) {
        const idSet = new Set(active.supporting_event_ids);
        list = list.filter(e => idSet.has(e.id));
      }
    }

    if (categoryFilter !== 'ALL') {
      list = list.filter(e => (e.category || '').toUpperCase().includes(categoryFilter));
    }

    if (severityFilter !== 'ALL') {
      list = list.filter(e => getSevTier(e.severity_score) === severityFilter);
    }

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(e =>
        (e.user || '').toLowerCase().includes(q) ||
        (e.source_ip || '').toLowerCase().includes(q) ||
        (e.host || '').toLowerCase().includes(q) ||
        (e.event_type || '').toLowerCase().includes(q) ||
        (e.action || '').toLowerCase().includes(q) ||
        (e.id || '').toLowerCase().includes(q)
      );
    }

    return list;
  }, [events, alerts, selectedAlertId, categoryFilter, severityFilter, search]);

  // ── 2. Time Window Bounds ──────────────────────────────────────────────────
  const { startMs, endMs } = useMemo(() => {
    if (filteredEvents.length === 0) {
      const now = Date.now();
      return { startMs: now - 3600_000, endMs: now };
    }
    const times = filteredEvents.map(e => parseTs(e.timestamp)?.getTime()).filter(Boolean);
    if (times.length === 0) {
      const now = Date.now();
      return { startMs: now - 3600_000, endMs: now };
    }
    const min = Math.min(...times);
    const max = Math.max(...times);
    const pad = Math.max(60_000, (max - min) * 0.05);
    return { startMs: min - pad, endMs: max + pad };
  }, [filteredEvents]);

  // ── 3. Cluster events within CLUSTER_THRESHOLD_MS ─────────────────────────
  const clusters = useMemo(() => {
    if (filteredEvents.length === 0) return [];
    const result = [];
    let cur = null;

    for (const ev of filteredEvents) {
      const t = parseTs(ev.timestamp)?.getTime();
      if (!t) continue;

      if (!cur) {
        cur = { representativeMs: t, events: [ev] };
      } else if (t - cur.representativeMs <= CLUSTER_THRESHOLD_MS) {
        cur.events.push(ev);
        // Representative becomes highest severity in cluster
        const best = cur.events.reduce((acc, x) => (x.severity_score ?? 0) > (acc.severity_score ?? 0) ? x : acc);
        cur.representativeMs = parseTs(best.timestamp)?.getTime() || cur.representativeMs;
      } else {
        result.push(cur);
        cur = { representativeMs: t, events: [ev] };
      }
    }
    if (cur) result.push(cur);
    return result;
  }, [filteredEvents]);

  // Active cluster object
  const selectedCluster = selectedClusterIdx !== null ? clusters[selectedClusterIdx] : null;

  // ── 4. Keyboard navigation on the ruler ────────────────────────────────────
  const handleMarkerKeyDown = useCallback((e, idx) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      setSelectedClusterIdx(Math.min(clusters.length - 1, idx + 1));
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      setSelectedClusterIdx(Math.max(0, idx - 1));
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setSelectedClusterIdx(selectedClusterIdx === idx ? null : idx);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setSelectedClusterIdx(null);
    }
  }, [clusters.length, selectedClusterIdx]);

  // Summary counts
  const summaryStats = useMemo(() => {
    const total = filteredEvents.length;
    const high = filteredEvents.filter(e => (e.severity_score ?? 0) >= 7.0).length;
    const medium = filteredEvents.filter(e => (e.severity_score ?? 0) >= 4.5 && (e.severity_score ?? 0) < 7.0).length;
    const low = total - high - medium;
    return { total, high, medium, low };
  }, [filteredEvents]);

  // Tick marks for ruler
  const tickLabels = useMemo(() => {
    const ticks = [];
    const count = 5;
    const span = endMs - startMs;
    for (let i = 0; i <= count; i++) {
      const ms = startMs + (span * (i / count));
      const pct = (i / count) * 100;
      ticks.push({ ms, pct });
    }
    return ticks;
  }, [startMs, endMs]);

  const clusterTier = (c) => {
    const maxScore = Math.max(...c.events.map(e => e.severity_score ?? 0));
    return getTierStyle(maxScore);
  };

  const clusterCategory = (c) => {
    return getCategoryStyle(c.events[0]?.category);
  };

  return (
    <div className="space-y-5">
      {/* ── Filter & Header Bar ────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-[#0F172A] tracking-tight flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#0284C7]" />
              <span>Incident Investigation Chronological Timeline</span>
            </h2>
            <p className="text-xs text-[#64748B] mt-0.5">
              High-precision timeline ruler. Select any diamond marker to inspect full event context below.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Alert scope dropdown */}
            {alerts && alerts.length > 0 && (
              <select
                value={selectedAlertId}
                onChange={e => {
                  setSelectedAlertId(e.target.value);
                  setSelectedClusterIdx(null);
                }}
                className="bg-white border border-[#DDE3EA] rounded-md px-2.5 py-1.5 text-xs text-[#0F172A] font-mono focus:outline-none focus:border-[#0284C7] shadow-subtle"
                aria-label="Filter by incident scope"
              >
                <option value="ALL">All Ingested Incidents &amp; Telemetry</option>
                {alerts.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.id} ({a.severity}) — {a.title.substring(0, 32)}...
                  </option>
                ))}
              </select>
            )}

            {/* Category filter */}
            <div className="flex items-center rounded-md bg-[#F0F3F6] border border-[#DDE3EA] p-0.5 text-xs shadow-subtle" role="group">
              {[
                { key: 'ALL', label: 'All' },
                { key: 'AUTH', label: 'Auth' },
                { key: 'SYS', label: 'System' },
                { key: 'NET', label: 'Network' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setCategoryFilter(key)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                    categoryFilter === key ? 'bg-[#0284C7] text-white shadow-sm' : 'text-[#475569] hover:text-[#0F172A]'
                  }`}
                  aria-pressed={categoryFilter === key}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Severity tier filter */}
            <div className="flex items-center rounded-md bg-[#F0F3F6] border border-[#DDE3EA] p-0.5 text-xs shadow-subtle" role="group">
              {[
                { key: 'ALL',    label: 'All Sev' },
                { key: 'HIGH',   label: '🔴 High' },
                { key: 'MEDIUM', label: '🟠 Med' },
                { key: 'LOW',    label: '🔵 Info' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setSeverityFilter(key)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                    severityFilter === key ? 'bg-[#0284C7] text-white shadow-sm' : 'text-[#475569] hover:text-[#0F172A]'
                  }`}
                  aria-pressed={severityFilter === key}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#94A3B8] pointer-events-none" />
              <input
                type="text"
                placeholder="Search user, IP, action…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-2.5 py-1.5 text-xs text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#0284C7] w-40 shadow-subtle"
              />
            </div>
          </div>
        </div>

        {/* Selected Incident Banner */}
        {activeAlert && (
          <div className="p-3 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-[#0284C7] bg-[#E0F2FE] px-2 py-0.5 rounded border border-[#BAE6FD]">
                {activeAlert.id}
              </span>
              <span className="font-semibold text-[#0F172A] truncate max-w-md">{activeAlert.title}</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-[#64748B] font-mono shrink-0">
              <span>Window: {fmtShort(activeAlert.first_seen)} → {fmtShort(activeAlert.last_seen)} UTC</span>
              <span className="font-bold text-[#0F172A]">{activeAlert.supporting_event_ids?.length || filteredEvents.length} events</span>
            </div>
          </div>
        )}

        {/* Summary metric counters */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            { label: 'Timeline Events', value: summaryStats.total,  color: 'text-[#0F172A]' },
            { label: '🔴 High Risk',     value: summaryStats.high,   color: 'text-[#DC2626]' },
            { label: '🟠 Attention',     value: summaryStats.medium, color: 'text-[#D97706]' },
            { label: '🔵 Informational', value: summaryStats.low,    color: 'text-[#0284C7]' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg px-3 py-2 shadow-subtle">
              <p className="text-[10px] text-[#64748B] uppercase tracking-wide font-medium">{label}</p>
              <p className={`text-base font-bold font-mono ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Legend row */}
        <div className="pt-2 border-t border-[#E2E8F0] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[10px] uppercase font-bold text-[#64748B] tracking-wider">Categories:</span>
            <LegendItem dotColor={CATEGORY_STYLE.AUTHENTICATION.fillColor} label="Authentication" />
            <LegendItem dotColor={CATEGORY_STYLE.SYSTEM.fillColor} label="System" />
            <LegendItem dotColor={CATEGORY_STYLE.NETWORK.fillColor} label="Network" />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[10px] uppercase font-bold text-[#64748B] tracking-wider">Severity Notations:</span>
            <LegendItem dotColor={TIER_STYLE.HIGH.colorHex} label="High Risk Diamond (≥ 7.0)" isDiamond />
            <LegendItem dotColor={TIER_STYLE.MEDIUM.colorHex} label="Attention Diamond (≥ 4.5)" isDiamond />
            <LegendItem dotColor={TIER_STYLE.LOW.colorHex} label="Info Diamond (< 4.5)" isDiamond />
          </div>
        </div>
      </div>

      {/* ── Timeline Ruler Card (Phase 3A: Clean Diamond Markers without Overlapping Timestamps) ── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-6 shadow-card">
        {clusters.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 gap-3 text-center">
            <ShieldAlert className="w-10 h-10 text-[#CBD5E1]" />
            <p className="text-sm font-semibold text-[#0F172A]">No chronological events match the current filter.</p>
            <p className="text-xs text-[#64748B] max-w-sm">
              {search || severityFilter !== 'ALL' || categoryFilter !== 'ALL' || selectedAlertId !== 'ALL'
                ? 'Try adjusting or clearing your category, severity, or search filters.'
                : 'Upload a log file or load the sample scenario from the top navigation.'}
            </p>
          </div>
        ) : (
          <>
            <div
              className="relative select-none"
              role="list"
              aria-label="Incident investigation time ruler"
            >
              {/* Date Header */}
              <div className="flex items-center justify-between mb-4">
                <span className="text-[11px] font-mono font-bold text-[#475569] bg-[#F1F5F9] px-2.5 py-1 rounded border border-[#E2E8F0]">
                  📅 Active Window: {fmtDate(new Date(startMs).toISOString())}
                  {fmtDate(new Date(startMs).toISOString()) !== fmtDate(new Date(endMs).toISOString()) &&
                    ` → ${fmtDate(new Date(endMs).toISOString())}`}
                </span>
                <span className="text-[10px] text-[#64748B]">
                  Use <kbd className="bg-[#F1F5F9] border px-1 rounded font-mono">←</kbd> <kbd className="bg-[#F1F5F9] border px-1 rounded font-mono">→</kbd> arrow keys to navigate events
                </span>
              </div>

              {/* Dedicated High-Precision Ruler Track (Height 80px)
                  - Diamonds positioned on baseline (top-8)
                  - Tick lines extend downwards (top-8 to top-12)
                  - Timestamps rendered below ticks (top-14)
                  => Markers NEVER obscure or collide with timestamps!
              */}
              <div className="relative h-24 my-2 border border-[#E2E8F0] rounded-xl bg-[#F8FAFC] px-6 overflow-visible">
                {/* Horizontal Baseline Axis */}
                <div className="absolute inset-x-6 top-8 h-[2px] bg-[#CBD5E1] rounded-full" />

                {/* Vertical Tick Marks & Timestamp Labels (Cleanly Below Baseline) */}
                {tickLabels.map((tick, i) => (
                  <div
                    key={i}
                    className="absolute flex flex-col items-center pointer-events-none"
                    style={{ left: `${tick.pct}%`, transform: 'translateX(-50%)' }}
                  >
                    {/* Tick line from baseline downwards */}
                    <div className="absolute top-8 w-px h-3.5 bg-[#94A3B8]" />
                    {/* Timestamp label below tick line */}
                    <span className="absolute top-13 font-mono text-[10px] text-[#64748B] whitespace-nowrap font-medium">
                      {fmtShort(new Date(tick.ms).toISOString())}
                    </span>
                  </div>
                ))}

                {/* Event Markers: Compact Sleek Diamond Notations on Baseline */}
                {clusters.map((cluster, idx) => {
                  const pct = calcPosition(cluster.representativeMs, startMs, endMs) * 100;
                  const isSelected = selectedClusterIdx === idx;
                  const tier = clusterTier(cluster);
                  const cat = clusterCategory(cluster);
                  const hasGroup = cluster.events.length > 1;
                  const timeLabel = fmtShort(new Date(cluster.representativeMs).toISOString());
                  const primaryEvent = cluster.events[0];
                  const friendlyName = friendlyLabel(primaryEvent?.event_type);

                  return (
                    <div
                      key={idx}
                      className="absolute group z-20"
                      style={{ 
                        left: `${pct}%`, 
                        top: '32px', // Centered on baseline
                        transform: 'translate(-50%, -50%)' 
                      }}
                      role="listitem"
                    >
                      {/* Interactive Diamond Button */}
                      <button
                        type="button"
                        onClick={() => setSelectedClusterIdx(isSelected ? null : idx)}
                        onKeyDown={e => handleMarkerKeyDown(e, idx)}
                        className={`
                          relative flex items-center justify-center rotate-45 transition-all duration-150 cursor-pointer
                          focus:outline-none focus-visible:ring-2 focus-visible:ring-[#0284C7] focus-visible:ring-offset-2
                          ${isSelected
                            ? 'w-5 h-5 shadow-lg scale-125 z-30'
                            : 'w-3.5 h-3.5 hover:scale-135 shadow-sm hover:z-30'
                          }
                        `}
                        style={{
                          backgroundColor: tier.diamondColor,
                          border: `2px solid ${isSelected ? '#FFFFFF' : tier.borderDark}`
                        }}
                        aria-pressed={isSelected}
                        aria-label={`Event: ${friendlyName} at ${timeLabel} UTC, Severity: ${tier.label}`}
                      >
                        {/* Center inner glyph in category color */}
                        <div 
                          className="w-1.5 h-1.5 rounded-full" 
                          style={{ backgroundColor: cat.fillColor }} 
                        />
                      </button>

                      {/* Group cluster badge count */}
                      {hasGroup && (
                        <span 
                          className="absolute -top-3.5 -right-3.5 w-4 h-4 rounded-full bg-white border border-[#CBD5E1] text-[8px] font-bold text-[#0F172A] flex items-center justify-center shadow-subtle pointer-events-none z-30"
                          title={`${cluster.events.length} events grouped in this time window`}
                        >
                          {cluster.events.length}
                        </span>
                      )}

                      {/* Accessible Floating Hover/Focus Tooltip */}
                      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:flex group-focus:flex flex-col items-center pointer-events-none z-40 whitespace-nowrap">
                        <div className="bg-[#0F172A] text-white px-2.5 py-1.5 rounded-lg shadow-xl text-[10px] space-y-0.5 border border-[#334155]">
                          <div className="font-bold flex items-center gap-1.5">
                            <span>{tier.icon}</span>
                            <span>{friendlyName}</span>
                          </div>
                          <div className="font-mono text-[#94A3B8] flex items-center gap-2">
                            <span>{timeLabel} UTC</span>
                            <span>•</span>
                            <span style={{ color: tier.colorHex }}>{tier.label} ({primaryEvent.severity_score ?? 1.0}/10)</span>
                          </div>
                          <div className="text-[9px] text-[#CBD5E1] truncate max-w-xs">
                            {primaryEvent.user ? `User: ${primaryEvent.user}` : ''} {primaryEvent.source_ip ? `IP: ${primaryEvent.source_ip}` : ''}
                          </div>
                        </div>
                        {/* Downward tooltip beak */}
                        <div className="w-2 h-2 bg-[#0F172A] rotate-45 -mt-1" />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Start & End Window Labels */}
              <div className="flex justify-between mt-2 pt-1">
                <div>
                  <p className="text-[9px] text-[#64748B] uppercase tracking-wider font-bold">Window Start</p>
                  <p className="font-mono text-[10px] text-[#475569]">{fmtShort(new Date(startMs).toISOString())} UTC</p>
                </div>
                <div className="text-right">
                  <p className="text-[9px] text-[#64748B] uppercase tracking-wider font-bold">Window End</p>
                  <p className="font-mono text-[10px] text-[#475569]">{fmtShort(new Date(endMs).toISOString())} UTC</p>
                </div>
              </div>
            </div>

            {/* ── Phase 3B: Selected Event Investigation Panel (or Helpful Empty State) ── */}
            {selectedCluster ? (
              <SelectedEventPanel
                cluster={selectedCluster}
                clusterIndex={selectedClusterIdx}
                totalClusters={clusters.length}
                allFilteredEvents={filteredEvents}
                onPrev={() => setSelectedClusterIdx(i => Math.max(0, i - 1))}
                onNext={() => setSelectedClusterIdx(i => Math.min(clusters.length - 1, i + 1))}
                onClose={() => setSelectedClusterIdx(null)}
                onInspectEvent={onInspectEvent}
                alerts={alerts}
              />
            ) : (
              /* Meaningful Empty State Beneath Timeline (Phase 3B requirement) */
              <div className="mt-6 rounded-xl border border-dashed border-[#CBD5E1] bg-[#F8FAFC] p-8 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-full bg-white border border-[#E2E8F0] flex items-center justify-center text-[#0284C7] shadow-subtle">
                  <Eye className="w-5 h-5 text-[#0284C7]" />
                </div>
                <div className="max-w-md mx-auto space-y-1">
                  <h3 className="text-sm font-bold text-[#0F172A]">No Event Selected for In-Depth Investigation</h3>
                  <p className="text-xs text-[#64748B] leading-relaxed">
                    Click any diamond marker on the timeline ruler above, or press <kbd className="bg-white border px-1.5 py-0.5 rounded font-mono text-[10px] shadow-2xs">←</kbd> and <kbd className="bg-white border px-1.5 py-0.5 rounded font-mono text-[10px] shadow-2xs">→</kbd> to inspect the forensic details, entity associations, and evidence context.
                  </p>
                </div>
                <div className="inline-flex items-center gap-3 bg-white border border-[#E2E8F0] px-3.5 py-1.5 rounded-lg text-xs font-mono text-[#475569] shadow-subtle">
                  <span>Visible Events: <strong>{filteredEvents.length}</strong></span>
                  <span>•</span>
                  <span>Timeline Clusters: <strong>{clusters.length}</strong></span>
                  <span>•</span>
                  <span className="text-[#DC2626]">High Risk: <strong>{summaryStats.high}</strong></span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
