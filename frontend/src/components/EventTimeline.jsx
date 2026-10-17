import React, { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import {
  Clock, ShieldAlert, ExternalLink, ChevronLeft, ChevronRight,
  X, Info, User, Monitor, Globe, Activity, Search, Filter,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Eye,
  Layers, Database
} from 'lucide-react';

// ─── Constants ────────────────────────────────────────────────────────────────

const CLUSTER_THRESHOLD_MS = 45_000; // events within 45 s share a pin
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
  if (!d) return '??:??';
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
    ring:        'ring-[#DC2626]',
    badge:       'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]',
    text:        'text-[#C53030]',
    bg:          'bg-[#FEF2F2]',
    label:       'High Risk',
    icon:        '🔴',
    colorHex:    '#DC2626'
  },
  MEDIUM: {
    border:      'border-[#D97706]',
    ring:        'ring-[#D97706]',
    badge:       'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]',
    text:        'text-[#DD6B20]',
    bg:          'bg-[#FFFAF0]',
    label:       'Needs Attention',
    icon:        '🟠',
    colorHex:    '#D97706'
  },
  LOW: {
    border:      'border-[#2563EB]',
    ring:        'ring-[#2563EB]',
    badge:       'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]',
    text:        'text-[#1677C8]',
    bg:          'bg-[#F8FAFC]',
    label:       'Informational',
    icon:        '🔵',
    colorHex:    '#2563EB'
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

// ─── Sub-components ───────────────────────────────────────────────────────────
function LegendItem({ dotColor, label, isCategory = false }) {
  return (
    <span className="flex items-center gap-1.5 text-xs text-[#475569]">
      <span
        className={`w-3 h-3 rounded-full shrink-0 border ${isCategory ? 'border-white ring-1 ring-[#CBD5E1]' : ''}`}
        style={{ backgroundColor: dotColor }}
        aria-hidden="true"
      />
      <span>{label}</span>
    </span>
  );
}

function FieldRow({ label, value, mono = true }) {
  const display = value != null && value !== '' ? value : 'Not available';
  const isMissing = display === 'Not available';
  return (
    <div className="flex gap-2 text-xs leading-relaxed">
      <span className="text-[#657180] w-28 shrink-0">{label}</span>
      <span className={`${mono ? 'font-mono' : ''} ${isMissing ? 'text-[#94A3B8] italic' : 'text-[#252B33]'} break-all`}>
        {display}
      </span>
    </div>
  );
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────
function DetailPanel({ cluster, clusterIndex, total, onPrev, onNext, onClose, onInspectEvent }) {
  const [innerIdx, setInnerIdx] = useState(0);
  const [showTech, setShowTech] = useState(false);

  useEffect(() => {
    setInnerIdx(0);
    setShowTech(false);
  }, [clusterIndex]);

  const event = cluster.events[innerIdx];
  if (!event) return null;

  const tier = getTierStyle(event.severity_score);
  const catStyle = getCategoryStyle(event.category);
  const clusterSize = cluster.events.length;
  const label = friendlyLabel(event.event_type);
  const impact = impactNote(event.event_type);
  const next = nextStep(event.event_type);
  const explanation = event.explanation || event.what_happened || event.description || null;
  const corrRule = event.correlation_rule || event.rule_name || null;

  return (
    <div
      className={`mt-5 rounded-xl border ${tier.border} ${tier.bg} overflow-hidden shadow-card`}
      role="region"
      aria-label="Selected event details"
    >
      {/* Panel header bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#DDE3EA] bg-white">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Category Badge */}
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${catStyle.badge}`}>
            {catStyle.icon} {catStyle.label}
          </span>
          {/* Severity Badge */}
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${tier.badge}`}>
            {tier.icon} {tier.label} ({event.severity_score ? event.severity_score.toFixed(1) : '1.0'}/10)
          </span>
          <span className="text-sm font-semibold text-[#252B33]">{label}</span>
          {clusterSize > 1 && (
            <span className="text-[10px] text-[#657180] border border-[#DDE3EA] bg-[#F8FAFC] rounded px-1.5 py-0.5 font-mono">
              Event {innerIdx + 1} of {clusterSize} at this time
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {/* Within-cluster navigation */}
          {clusterSize > 1 && (
            <>
              <button onClick={() => setInnerIdx(i => Math.max(0, i - 1))} disabled={innerIdx === 0}
                className="p-1 rounded text-[#657180] hover:text-[#252B33] disabled:opacity-25 transition" aria-label="Previous event in group">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button onClick={() => setInnerIdx(i => Math.min(clusterSize - 1, i + 1))} disabled={innerIdx === clusterSize - 1}
                className="p-1 rounded text-[#657180] hover:text-[#252B33] disabled:opacity-25 transition" aria-label="Next event in group">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
              <div className="w-px h-4 bg-[#DDE3EA] mx-0.5" />
            </>
          )}
          {/* Cross-cluster navigation */}
          <button onClick={onPrev} disabled={clusterIndex === 0}
            className="p-1 rounded text-[#657180] hover:text-[#1677C8] disabled:opacity-25 transition" aria-label="Previous pin">
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
          <span className="font-mono text-[10px] text-[#657180] px-0.5 select-none">
            {clusterIndex + 1}/{total}
          </span>
          <button onClick={onNext} disabled={clusterIndex === total - 1}
            className="p-1 rounded text-[#657180] hover:text-[#1677C8] disabled:opacity-25 transition" aria-label="Next pin">
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
          <div className="w-px h-4 bg-[#DDE3EA] mx-0.5" />
          <button onClick={onClose}
            className="p-1 rounded text-[#657180] hover:text-[#C53030] transition" aria-label="Close details panel">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main content — beginner-friendly questions */}
      <div className="p-4 space-y-4">
        {/* Q1 – What happened? */}
        <div>
          <p className={`text-[10px] font-bold uppercase tracking-widest mb-1 ${tier.text}`}>
            🔍 What happened?
          </p>
          <p className="text-sm text-[#252B33] leading-relaxed">
            {explanation || `The system detected: ${label.toLowerCase()} for account '${event.user || 'system'}' on host ${event.host || 'endpoint'}.`}
          </p>
        </div>

        {/* Q2 – When did it happen? */}
        <div>
          <p className={`text-[10px] font-bold uppercase tracking-widest mb-1 ${tier.text}`}>
            🕐 When did it happen?
          </p>
          <p className="font-mono text-sm text-[#252B33] font-medium">{fmtFull(event.timestamp)}</p>
        </div>

        {/* Q3 – Why was it flagged? */}
        <div>
          <p className={`text-[10px] font-bold uppercase tracking-widest mb-1 ${tier.text}`}>
            ⚠️ Why was it flagged?
          </p>
          <p className="text-sm text-[#475569] leading-relaxed">
            {corrRule
              ? `The detection rule "${corrRule.replace(/_/g, ' ')}" identified this pattern as suspicious based on the event sequence and parameters.`
              : `Matched detection criteria with severity score of ${event.severity_score ? event.severity_score.toFixed(1) : '1.0'}/10.0 and action '${event.action || event.status || 'observed'}'.`}
          </p>
        </div>

        {/* Q4 – Why might it matter? */}
        <div>
          <p className={`text-[10px] font-bold uppercase tracking-widest mb-1 ${tier.text}`}>
            ❗ Why might it matter?
          </p>
          <p className="text-sm text-[#475569] leading-relaxed">{impact}</p>
        </div>

        {/* Q5 – What should I investigate next? */}
        <div>
          <p className={`text-[10px] font-bold uppercase tracking-widest mb-1 ${tier.text}`}>
            ✅ What should I investigate next?
          </p>
          <p className="text-sm text-[#475569] leading-relaxed">{next}</p>
        </div>

        {/* Technical details accordion */}
        <div className="border-t border-[#DDE3EA] pt-3">
          <button
            type="button"
            onClick={() => setShowTech(v => !v)}
            className="flex items-center gap-2 text-xs text-[#657180] hover:text-[#252B33] font-medium transition"
            aria-expanded={showTech}
          >
            {showTech ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            <span>{showTech ? 'Hide technical details' : 'Show technical details'}</span>
          </button>

          {showTech && (
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-white p-3.5 rounded-lg border border-[#DDE3EA]">
              <div className="space-y-1.5">
                <FieldRow label="Event ID"      value={event.id} />
                <FieldRow label="Severity score" value={event.severity_score != null ? `${event.severity_score.toFixed(1)} / 10` : null} />
                <FieldRow label="Category"      value={event.category} />
                <FieldRow label="Event type"    value={event.event_type} />
                <FieldRow label="Action"        value={event.action} />
                <FieldRow label="User"          value={event.user} />
                <FieldRow label="Source host"   value={event.host} />
                <FieldRow label="Source IP"     value={event.source_ip} />
                <FieldRow label="Destination"   value={event.dest_host || event.dest_ip} />
                <FieldRow label="Protocol"      value={event.protocol} />
                {event.bytes_out != null && (
                  <FieldRow label="Bytes out" value={`${(event.bytes_out / 1024).toFixed(1)} KB`} />
                )}
                <FieldRow label="Correlation rule" value={corrRule} />
              </div>

              <div>
                {event.raw_log ? (
                  <div>
                    <p className="text-[10px] text-[#657180] uppercase tracking-wider mb-1 font-semibold">Raw log entry</p>
                    <pre className="bg-[#F8FAFC] border border-[#DDE3EA] rounded p-2 text-[10px] font-mono text-[#252B33] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed max-h-32">
                      {event.raw_log}
                    </pre>
                  </div>
                ) : (
                  <p className="text-xs text-[#94A3B8] italic">No raw log entry available for this event.</p>
                )}

                <button
                  type="button"
                  onClick={() => onInspectEvent(event)}
                  className="mt-3 flex items-center gap-1.5 text-xs font-semibold text-[#1677C8] hover:text-[#1366AC] transition"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Open in Forensic Evidence Inspector</span>
                </button>
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
      list = list.filter(e => {
        const c = (e.category || '').toUpperCase();
        if (categoryFilter === 'AUTHENTICATION') return c.includes('AUTH');
        if (categoryFilter === 'SYSTEM') return c.includes('SYS');
        if (categoryFilter === 'NETWORK') return c.includes('NET');
        return true;
      });
    }

    if (severityFilter !== 'ALL') {
      list = list.filter(e => getSevTier(e.severity_score) === severityFilter);
    }

    if (search) {
      const q = search.toLowerCase();
      list = list.filter(e =>
        (e.user       && e.user.toLowerCase().includes(q)) ||
        (e.host       && e.host.toLowerCase().includes(q)) ||
        (e.event_type && e.event_type.toLowerCase().includes(q)) ||
        (e.raw_log    && e.raw_log.toLowerCase().includes(q))
      );
    }
    return list;
  }, [events, alerts, selectedAlertId, categoryFilter, severityFilter, search]);

  // ── 2. Summary counts ──────────────────────────────────────────────────────
  const summaryStats = useMemo(() => {
    if (!events) return { total: 0, high: 0, medium: 0, low: 0 };
    return {
      total:  filteredEvents.length,
      high:   filteredEvents.filter(e => getSevTier(e.severity_score) === 'HIGH').length,
      medium: filteredEvents.filter(e => getSevTier(e.severity_score) === 'MEDIUM').length,
      low:    filteredEvents.filter(e => getSevTier(e.severity_score) === 'LOW').length,
    };
  }, [filteredEvents, events]);

  // ── 3. Ruler range ─────────────────────────────────────────────────────────
  const { startMs, endMs, spanMs } = useMemo(() => {
    const valid = filteredEvents.map(e => parseTs(e.timestamp)).filter(Boolean).map(d => d.getTime());
    if (valid.length === 0) return { startMs: 0, endMs: 0, spanMs: 0 };
    const lo = Math.min(...valid);
    const hi = Math.max(...valid);
    const pad = Math.max((hi - lo) * 0.05, 60_000);
    return { startMs: lo - pad, endMs: hi + pad, spanMs: (hi + pad) - (lo - pad) };
  }, [filteredEvents]);

  // ── 4. Cluster overlapping events ─────────────────────────────────────────
  const clusters = useMemo(() => {
    if (spanMs === 0 || filteredEvents.length === 0) return [];
    const sorted = filteredEvents
      .map(e => ({ event: e, ms: parseTs(e.timestamp)?.getTime() ?? null }))
      .filter(x => x.ms !== null)
      .sort((a, b) => a.ms - b.ms);

    const groups = [];
    for (const item of sorted) {
      const last = groups[groups.length - 1];
      if (last && item.ms - last.representativeMs <= CLUSTER_THRESHOLD_MS) {
        last.events.push(item.event);
        last.representativeMs = (last.representativeMs * (last.events.length - 1) + item.ms) / last.events.length;
      } else {
        groups.push({ representativeMs: item.ms, events: [item.event] });
      }
    }
    return groups;
  }, [filteredEvents, spanMs]);

  // ── 5. Reset selection when filters change ────────────────────────────────
  useEffect(() => { setSelectedClusterIdx(null); }, [selectedAlertId, categoryFilter, severityFilter, search]);

  // ── 6. Keyboard nav on the ruler ─────────────────────────────────────────
  const handlePinKeyDown = useCallback((e, idx) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedClusterIdx(i => (i === idx ? null : idx)); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); setSelectedClusterIdx(i => Math.min(clusters.length - 1, (i ?? -1) + 1)); }
    else if (e.key === 'ArrowLeft')  { e.preventDefault(); setSelectedClusterIdx(i => Math.max(0, (i ?? clusters.length) - 1)); }
    else if (e.key === 'Escape')     { setSelectedClusterIdx(null); }
  }, [clusters.length, selectedClusterIdx]);

  const selectedCluster = selectedClusterIdx !== null ? clusters[selectedClusterIdx] : null;

  // Dominant severity of a cluster = highest score in it
  const clusterTier = (cluster) => getTierStyle(Math.max(...cluster.events.map(e => e.severity_score ?? 0)));
  const clusterCategory = (cluster) => getCategoryStyle(cluster.events[0]?.category);

  // Ruler tick labels
  const tickLabels = useMemo(() => {
    if (spanMs === 0) return [];
    return [0, 1, 2, 3, 4].map(i => ({ pct: i * 25, ms: startMs + spanMs * i / 4 }));
  }, [startMs, spanMs]);

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">

      {/* ── Controls & Summary Bar ───────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 lg:p-5 space-y-4 shadow-card">

        {/* Heading */}
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
          <div>
            <h1 className="text-base font-bold text-[#252B33] flex items-center gap-2">
              <Clock className="w-5 h-5 text-[#1677C8]" aria-hidden="true" />
              Incident Investigation Timeline
            </h1>
            <p className="text-xs text-[#657180] mt-0.5">
              Follow suspicious activity in chronological order. Select a marker to see what happened and why it matters.
            </p>
          </div>

          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Alert scope */}
            <div className="relative">
              <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#94A3B8] pointer-events-none" aria-hidden="true" />
              <select
                value={selectedAlertId}
                onChange={e => setSelectedAlertId(e.target.value)}
                className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-3 py-1.5 text-xs text-[#252B33] focus:outline-none focus:border-[#1677C8] shadow-subtle font-medium"
                aria-label="Filter timeline by incident"
              >
                <option value="ALL">All Events / Global Scope</option>
                {alerts?.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.id} — {a.title?.substring(0, 30)}…
                  </option>
                ))}
              </select>
            </div>

            {/* Category filter */}
            <div className="flex items-center rounded-md bg-[#F0F3F6] border border-[#DDE3EA] p-0.5 text-xs shadow-subtle" role="group" aria-label="Filter by event category">
              {[
                { key: 'ALL',            label: 'All Types' },
                { key: 'AUTHENTICATION', label: '🟣 Auth' },
                { key: 'SYSTEM',         label: '🔵 System' },
                { key: 'NETWORK',        label: '🟢 Network' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setCategoryFilter(key)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                    categoryFilter === key ? 'bg-[#1677C8] text-white shadow-sm' : 'text-[#475569] hover:text-[#252B33]'
                  }`}
                  aria-pressed={categoryFilter === key}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Severity tier filter */}
            <div className="flex items-center rounded-md bg-[#F0F3F6] border border-[#DDE3EA] p-0.5 text-xs shadow-subtle" role="group" aria-label="Filter by risk level">
              {[
                { key: 'ALL',    label: 'All Severity' },
                { key: 'HIGH',   label: '🔴 High Risk' },
                { key: 'MEDIUM', label: '🟠 Attention' },
                { key: 'LOW',    label: '🔵 Info' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setSeverityFilter(key)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                    severityFilter === key ? 'bg-[#1677C8] text-white shadow-sm' : 'text-[#475569] hover:text-[#252B33]'
                  }`}
                  aria-pressed={severityFilter === key}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#94A3B8] pointer-events-none" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search events…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-2.5 py-1.5 text-xs text-[#252B33] placeholder-[#94A3B8] focus:outline-none focus:border-[#1677C8] w-32 shadow-subtle"
                aria-label="Search events"
              />
            </div>
          </div>
        </div>

        {/* Selected Incident Banner (if filtered to an alert) */}
        {activeAlert && (
          <div className="p-3 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-[#1677C8] bg-[#EAF3FB] px-2 py-0.5 rounded border border-[#BFDBFE]">
                {activeAlert.id}
              </span>
              <span className="font-semibold text-[#252B33] truncate max-w-md">{activeAlert.title}</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-[#657180] font-mono shrink-0">
              <span>Window: {fmtShort(activeAlert.first_seen)} → {fmtShort(activeAlert.last_seen)} UTC</span>
              <span className="font-bold text-[#252B33]">{activeAlert.supporting_event_ids?.length || filteredEvents.length} events</span>
            </div>
          </div>
        )}

        {/* Summary counters */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            { label: 'Relevant Events',  value: summaryStats.total,  color: 'text-[#252B33]' },
            { label: '🔴 High Risk',      value: summaryStats.high,   color: 'text-[#C53030]' },
            { label: '🟠 Need Attention', value: summaryStats.medium, color: 'text-[#DD6B20]' },
            { label: '🔵 Informational',  value: summaryStats.low,    color: 'text-[#1677C8]' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg px-3 py-2 shadow-subtle">
              <p className="text-[10px] text-[#657180] uppercase tracking-wide font-medium">{label}</p>
              <p className={`text-lg font-bold font-mono ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Legends: Distinct Category and Severity Legends */}
        <div className="pt-2 border-t border-[#DDE3EA] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          {/* Categories */}
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[10px] uppercase font-bold text-[#657180] tracking-wider">Categories:</span>
            <LegendItem dotColor={CATEGORY_STYLE.AUTHENTICATION.fillColor} label="Authentication" isCategory />
            <LegendItem dotColor={CATEGORY_STYLE.SYSTEM.fillColor} label="System" isCategory />
            <LegendItem dotColor={CATEGORY_STYLE.NETWORK.fillColor} label="Network" isCategory />
          </div>

          {/* Severities */}
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[10px] uppercase font-bold text-[#657180] tracking-wider">Severities:</span>
            <LegendItem dotColor={TIER_STYLE.HIGH.colorHex} label="High Risk (≥ 7.0)" />
            <LegendItem dotColor={TIER_STYLE.MEDIUM.colorHex} label="Needs Attention (≥ 4.5)" />
            <LegendItem dotColor={TIER_STYLE.LOW.colorHex} label="Informational (< 4.5)" />
          </div>
        </div>
      </div>

      {/* ── Ruler Card ────────────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-6 shadow-card">
        {clusters.length === 0 ? (
          /* Empty state */
          <div className="flex flex-col items-center justify-center py-14 gap-3 text-center">
            <ShieldAlert className="w-10 h-10 text-[#CBD5E1]" aria-hidden="true" />
            <p className="text-sm font-semibold text-[#252B33]">No chronological events match the current filter.</p>
            <p className="text-xs text-[#657180] max-w-sm">
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
              {/* Date header */}
              <p className="text-[10px] text-[#657180] mb-3 font-mono font-medium" aria-label="Timeline date">
                {fmtDate(new Date(startMs).toISOString())}
                {fmtDate(new Date(startMs).toISOString()) !== fmtDate(new Date(endMs).toISOString()) &&
                  ` — ${fmtDate(new Date(endMs).toISOString())}`}
              </p>

              {/* Ruler area */}
              <div className="relative h-14 flex items-center">
                {/* Baseline bar */}
                <div className="absolute inset-x-0 top-1/2 -translate-y-1/2 h-[2px] bg-[#CBD5E1] rounded-full" aria-hidden="true" />

                {/* Tick marks */}
                {tickLabels.map((tick, i) => (
                  <div
                    key={i}
                    className="absolute flex flex-col items-center"
                    style={{ left: `${tick.pct}%`, transform: 'translateX(-50%)' }}
                    aria-hidden="true"
                  >
                    <div className="w-px h-3 bg-[#94A3B8]" />
                    <span className="mt-0.5 font-mono text-[9px] text-[#657180] whitespace-nowrap">
                      {fmtShort(new Date(tick.ms).toISOString())}
                    </span>
                  </div>
                ))}

                {/* Event markers / pins */}
                {clusters.map((cluster, idx) => {
                  const pct = calcPosition(cluster.representativeMs, startMs, endMs) * 100;
                  const isSelected = selectedClusterIdx === idx;
                  const tier = clusterTier(cluster);
                  const cat = clusterCategory(cluster);
                  const hasGroup = cluster.events.length > 1;
                  const timeLabel = fmtShort(new Date(cluster.representativeMs).toISOString());
                  const friendlyName = friendlyLabel(cluster.events[0]?.event_type);

                  return (
                    <div
                      key={idx}
                      className="absolute flex flex-col items-center group"
                      style={{ left: `${pct}%`, transform: 'translateX(-50%)' }}
                      role="listitem"
                    >
                      {/* Time label — always visible when selected, visible on hover otherwise */}
                      <span
                        className={`font-mono text-[9px] mb-1 whitespace-nowrap transition-opacity duration-150 ${
                          isSelected ? `opacity-100 ${tier.text} font-bold` : 'opacity-0 group-hover:opacity-100 text-[#657180]'
                        }`}
                        aria-hidden="true"
                      >
                        {timeLabel}
                      </span>

                      {/* Pin button: Ring in severity color, inner circle in category color */}
                      <button
                        type="button"
                        onClick={() => setSelectedClusterIdx(isSelected ? null : idx)}
                        onKeyDown={e => handlePinKeyDown(e, idx)}
                        className={`
                          relative flex items-center justify-center rounded-full border-2 transition-all duration-150 cursor-pointer
                          focus:outline-none focus-visible:ring-2 focus-visible:ring-[#1677C8]
                          ${tier.border}
                          ${isSelected
                            ? `w-5 h-5 ring-2 ring-offset-1 ${tier.ring} scale-125 shadow-md`
                            : 'w-4 h-4 hover:scale-125 shadow-sm'
                          }
                        `}
                        style={{ backgroundColor: cat.fillColor }}
                        aria-pressed={isSelected}
                        aria-label={`${hasGroup ? `${cluster.events.length} events grouped` : friendlyName} at ${timeLabel}, Category: ${cat.label}, Severity: ${tier.label}`}
                        title={`${hasGroup ? `${cluster.events.length} events` : friendlyName} (${cat.label}) — ${timeLabel}`}
                      >
                        {hasGroup && (
                          <span className="absolute -top-3 -right-3 w-4 h-4 rounded-full bg-white border border-[#CBD5E1] text-[8px] font-bold text-[#252B33] flex items-center justify-center shadow-subtle">
                            {cluster.events.length}
                          </span>
                        )}
                      </button>

                      {/* Stem when selected */}
                      {isSelected && (
                        <div className="w-px h-4 bg-[#94A3B8] mt-0.5" aria-hidden="true" />
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Start / End labels */}
              <div className="flex justify-between mt-5">
                <div>
                  <p className="text-[9px] text-[#657180] uppercase tracking-wider font-semibold">Start Window</p>
                  <p className="font-mono text-[10px] text-[#475569]">{fmtShort(new Date(startMs).toISOString())} UTC</p>
                </div>
                <div className="text-right">
                  <p className="text-[9px] text-[#657180] uppercase tracking-wider font-semibold">End Window</p>
                  <p className="font-mono text-[10px] text-[#475569]">{fmtShort(new Date(endMs).toISOString())} UTC</p>
                </div>
              </div>

              {/* Idle hint */}
              {selectedClusterIdx === null && (
                <p className="text-center text-[11px] text-[#657180] mt-3 italic">
                  👆 Select an event marker on the ruler to see what happened · use ← → arrow keys to navigate
                </p>
              )}
            </div>

            {/* Detail panel */}
            {selectedCluster && (
              <DetailPanel
                cluster={selectedCluster}
                clusterIndex={selectedClusterIdx}
                total={clusters.length}
                onPrev={() => setSelectedClusterIdx(i => Math.max(0, i - 1))}
                onNext={() => setSelectedClusterIdx(i => Math.min(clusters.length - 1, i + 1))}
                onClose={() => setSelectedClusterIdx(null)}
                onInspectEvent={onInspectEvent}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}
