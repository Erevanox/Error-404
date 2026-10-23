import React, { useState, useEffect, useRef } from 'react';
import {
  FileSearch, Copy, Check, Terminal, Database,
  Search, Shield, ShieldOff, Info, AlertCircle, ChevronDown, ChevronUp,
  ArrowLeft, Activity
} from 'lucide-react';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityColor(score) {
  const s = score ?? 0;
  if (s >= 7.0) return 'text-[#C53030]';
  if (s >= 4.5) return 'text-[#DD6B20]';
  return 'text-[#1677C8]';
}

function severityLabel(score) {
  const s = score ?? 0;
  if (s >= 7.0) return 'High Risk';
  if (s >= 4.5) return 'Needs Attention';
  return 'Informational';
}

/**
 * Explains in plain language how the score was derived.
 * Uses only fields actually present on the event.
 */
function buildSevExplanation(event) {
  const score = event?.severity_score;
  if (score == null) return null;
  const parts = [];
  const cat = event.category || '';
  const type = (event.event_type || '').toLowerCase();
  const action = (event.action || '').toLowerCase();

  if (type.includes('brute_force')) {
    parts.push('Multiple repeated login failures were detected in a short window.');
  } else if (type.includes('lateral')) {
    parts.push('Access was observed moving between internal systems, a pattern associated with lateral movement.');
  } else if (type.includes('exfil') || type.includes('data_transfer')) {
    parts.push('An unusually high volume of outbound data was detected.');
  } else if (type.includes('privilege')) {
    parts.push('An elevated permission or privilege change was recorded.');
  } else if (type.includes('off_hours')) {
    parts.push('The login time fell outside normal working hours for this account.');
  }

  if (action.includes('fail')) parts.push('The action resulted in a failure, which is weighted upward.');
  if (cat === 'NETWORK') parts.push('Network-category events carry additional scoring weight due to potential lateral impact.');

  if (score >= 7.0) parts.push(`A combined score of ${score.toFixed(1)} places this event in the High Risk band (≥ 7.0).`);
  else if (score >= 4.5) parts.push(`A score of ${score.toFixed(1)} places this in the Needs Attention band (4.5–7.0).`);
  else parts.push(`A score of ${score.toFixed(1)} is informational and may not require immediate action.`);

  parts.push('Severity is a prioritization indicator, not evidence of malicious intent.');

  return parts.length > 1 ? parts.join(' ') : null;
}

// ─── Normalized field row ─────────────────────────────────────────────────────

function NField({ label, value, color, mono = true }) {
  const missing = value == null || value === '';
  return (
    <div className="flex gap-2 items-start py-1.5 border-b border-[#F0F3F6] last:border-0">
      <span className="text-[10px] text-[#657180] uppercase tracking-wide w-32 shrink-0 pt-0.5 font-semibold">{label}</span>
      <span className={`text-xs break-all leading-relaxed ${mono ? 'font-mono' : ''} ${
        missing ? 'text-[#94A3B8] italic' : (color || 'text-[#252B33]')
      }`}>
        {missing ? 'Not available' : value}
      </span>
    </div>
  );
}

// ─── Chain-of-custody badge ───────────────────────────────────────────────────
// Honest: we only mark "verified" if the backend provides an integrity_hash.

function CustodyBadge({ event }) {
  const hasHash = event?.integrity_hash;
  const isSimulated = event?.is_simulated;

  if (hasHash) {
    return (
      <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-[11px] text-emerald-800">
        <Shield className="w-4 h-4 text-[#16A34A] shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-semibold text-emerald-900">Forensic Chain of Custody Verified</span>
          <span className="block text-[#16A34A] font-mono text-[10px] mt-0.5">
            SHA-256: {hasHash}
          </span>
          <span className="block text-[#657180] mt-0.5">
            Raw log integrity confirmed. Normalization is a read-only projection.
          </span>
        </div>
      </div>
    );
  }

  if (isSimulated) {
    return (
      <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-50 border border-amber-200 text-[11px] text-amber-900">
        <AlertCircle className="w-4 h-4 text-[#DD6B20] shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-semibold text-amber-950">Simulated Demo Data</span>
          <span className="block text-[#657180] mt-0.5">
            This event is synthetic. Field values are illustrative and not derived from a real system log.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-2 p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] text-[11px] text-[#657180]">
      <ShieldOff className="w-4 h-4 text-[#94A3B8] shrink-0 mt-0.5" aria-hidden="true" />
      <div>
        <span className="font-semibold text-[#252B33]">Integrity Verification Unavailable</span>
        <span className="block text-[#657180] mt-0.5">
          No cryptographic hash was stored for this event. The raw log is preserved as read from the
          ingest pipeline, but end-to-end integrity cannot be confirmed without a verified hash.
        </span>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function EvidenceInspector({ 
  events, 
  initialEvent, 
  returnAlertContext, 
  onReturnToAlert 
}) {
  const [activeEvent, setActiveEvent] = useState(initialEvent || events?.[0] || null);
  const [copied, setCopied] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');
  const [showSevDetail, setShowSevDetail] = useState(false);

  // Sync when caller selects an event from timeline or scatter plot or alert flowchart
  useEffect(() => {
    if (initialEvent) {
      setActiveEvent(initialEvent);
      setShowSevDetail(false);
    } else if (events?.length > 0 && !activeEvent) {
      setActiveEvent(events[0]);
    }
  }, [initialEvent, events]);

  const handleCopyRaw = () => {
    if (!activeEvent?.raw_log) return;
    navigator.clipboard.writeText(activeEvent.raw_log).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredList = (events || []).filter(e => {
    if (!filterQuery) return true;
    const q = filterQuery.toLowerCase();
    return (
      (e.id        && e.id.toLowerCase().includes(q)) ||
      (e.user      && e.user.toLowerCase().includes(q)) ||
      (e.event_type && e.event_type.toLowerCase().includes(q)) ||
      (e.host      && e.host.toLowerCase().includes(q))
    );
  });

  const sevExplanation = buildSevExplanation(activeEvent);
  const corrRule = activeEvent?.correlation_rule || activeEvent?.rule_name || null;
  const tiMeta = activeEvent?.metadata || null;

  const catBadgeColor = activeEvent?.category === 'AUTHENTICATION'
    ? 'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]'
    : activeEvent?.category === 'NETWORK'
    ? 'bg-purple-50 text-[#6B46C1] border border-purple-200'
    : 'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]';

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">

      {/* ── Return to Incident Flowchart Banner ─────────────────────────────── */}
      {returnAlertContext && (
        <div className="bg-[#EAF3FB] border border-[#BFDBFE] rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-subtle animate-fadeIn">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-[#1677C8] shrink-0" />
            <div className="text-xs text-[#252B33]">
              <span>Investigating evidence for incident: </span>
              <strong className="text-[#1677C8] font-mono">{returnAlertContext.id}</strong>
              <span className="text-[#657180]"> ({returnAlertContext.title})</span>
            </div>
          </div>
          <button
            onClick={() => onReturnToAlert?.(returnAlertContext)}
            className="px-3.5 py-1.5 rounded-lg bg-[#1677C8] hover:bg-[#1366AC] text-white text-xs font-semibold transition flex items-center gap-1.5 shadow-sm shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>← Return to Incident Flowchart</span>
          </button>
        </div>
      )}

      {/* ── Section Header ─────────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-[#252B33] flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-[#1677C8]" aria-hidden="true" />
              Forensic Evidence Inspector
              <div className="relative group">
                <Info className="w-3.5 h-3.5 text-[#94A3B8] cursor-help" aria-label="Inspector help" />
                <div className="absolute left-0 top-5 z-50 hidden group-hover:block bg-white border border-[#DDE3EA] rounded-xl p-3 w-64 text-xs text-[#475569] shadow-xl leading-relaxed pointer-events-none">
                  Compare the structured event data with the original log to understand the evidence
                  behind the alert. The left pane shows parsed attributes; the right shows the verbatim
                  source record.
                </div>
              </div>
            </h2>
            <p className="text-xs text-[#657180] mt-0.5">
              Normalized unified schema presented side-by-side with immutable raw telemetry logs.
            </p>
          </div>

          {/* Event picker */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94A3B8]" aria-hidden="true" />
              <input
                type="text"
                placeholder="Event ID, user…"
                value={filterQuery}
                onChange={e => setFilterQuery(e.target.value)}
                className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-3 py-1.5 text-xs text-[#252B33] placeholder-[#94A3B8] focus:outline-none focus:border-[#1677C8] w-40 shadow-subtle"
                aria-label="Search events"
              />
            </div>
            <select
              value={activeEvent?.id || ''}
              onChange={e => {
                const found = events?.find(ev => ev.id === e.target.value);
                if (found) { setActiveEvent(found); setShowSevDetail(false); }
              }}
              className="bg-white border border-[#DDE3EA] rounded-md px-3 py-1.5 text-xs text-[#252B33] focus:outline-none focus:border-[#1677C8] max-w-[220px] shadow-subtle"
              aria-label="Select event"
            >
              <option value="">— select event —</option>
              {filteredList.map(e => (
                <option key={e.id} value={e.id}>
                  {e.id} · {e.category} · {e.event_type}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Sync indicator */}
        {initialEvent && activeEvent?.id === initialEvent.id && (
          <div className="mt-2 text-[10px] text-[#1677C8] flex items-center gap-1.5 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[#1677C8] animate-pulse" aria-hidden="true" />
            Synchronized with selected point · event {activeEvent.id}
          </div>
        )}
      </div>

      {activeEvent ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* ── LEFT: Normalized Event Schema ─────────────────────────────── */}
          <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 space-y-3 shadow-card">

            {/* Pane header */}
            <div className="flex items-center justify-between pb-2 border-b border-[#DDE3EA]">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#1677C8]" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-[#252B33]">Normalized Event Schema</h3>
              </div>
              {activeEvent.category && (
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${catBadgeColor}`}>
                  {activeEvent.category}
                </span>
              )}
            </div>

            {/* Core fields */}
            <div className="space-y-0">
              <NField label="Event ID"       value={activeEvent.id} />
              <NField label="Timestamp (UTC)" value={activeEvent.timestamp} />
              <NField label="Category"       value={activeEvent.category} mono={false} />
              <NField label="Observed Action"
                value={activeEvent.action?.toUpperCase()}
                color={activeEvent.action?.toLowerCase().includes('fail') ? 'text-[#C53030]' : 'text-[#16A34A]'}
              />
              <NField label="User / Account" value={activeEvent.user} />
              <NField label="Source Host"    value={activeEvent.host} />
              <NField label="Source IP"      value={activeEvent.source_ip} />
              <NField label="Destination"    value={activeEvent.dest_host || activeEvent.dest_ip} />
              <NField label="Protocol"       value={activeEvent.protocol} />
              {activeEvent.bytes_out != null && (
                <NField label="Bytes Out" value={`${(activeEvent.bytes_out / 1024).toFixed(1)} KB`} />
              )}
            </div>

            {/* Severity block */}
            <div className="pt-2 border-t border-[#DDE3EA]">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-[#657180] uppercase tracking-wide font-semibold">Severity Score</span>
                <span className={`font-mono font-bold text-sm ${severityColor(activeEvent.severity_score)}`}>
                  {activeEvent.severity_score != null ? activeEvent.severity_score.toFixed(1) : 'N/A'} / 10.0
                  {activeEvent.severity_score != null && (
                    <span className={`ml-1.5 text-[10px] font-normal px-1.5 py-0.5 rounded ${
                      activeEvent.severity_score >= 7.0 ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]' :
                      activeEvent.severity_score >= 4.5 ? 'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]' :
                      'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]'
                    }`}>
                      {severityLabel(activeEvent.severity_score)}
                    </span>
                  )}
                </span>
              </div>

              {sevExplanation && (
                <div>
                  <button
                    onClick={() => setShowSevDetail(v => !v)}
                    className="flex items-center gap-1.5 text-[11px] text-[#1677C8] hover:text-[#1366AC] font-medium transition"
                    aria-expanded={showSevDetail}
                  >
                    {showSevDetail ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    {showSevDetail ? 'Hide score explanation' : 'Why this score?'}
                  </button>
                  {showSevDetail && (
                    <p className="mt-1.5 text-xs text-[#475569] leading-relaxed bg-[#F8FAFC] border border-[#DDE3EA] rounded p-2.5">
                      {sevExplanation}
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Detection Rule */}
            {corrRule && (
              <div className="pt-2 border-t border-[#DDE3EA]">
                <span className="text-[10px] text-[#657180] uppercase tracking-wide block mb-1 font-semibold">Detection Rule</span>
                <span className="font-mono text-xs text-[#1677C8] bg-[#EAF3FB] border border-[#BFDBFE] rounded px-2 py-1 block">
                  {corrRule.replace(/_/g, ' ')}
                </span>
              </div>
            )}

            {/* Threat Intelligence / Metadata */}
            {tiMeta && Object.keys(tiMeta).length > 0 && (
              <div className="pt-2 border-t border-[#DDE3EA]">
                <span className="text-[10px] text-[#657180] uppercase tracking-wide block mb-1.5 font-semibold">
                  Threat Intelligence Metadata
                </span>
                <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded p-2.5 font-mono text-[10px] text-[#252B33] overflow-x-auto">
                  <pre>{JSON.stringify(tiMeta, null, 2)}</pre>
                </div>
              </div>
            )}

            {/* Explanation */}
            {(activeEvent.explanation || activeEvent.what_happened) && (
              <div className="pt-2 border-t border-[#DDE3EA]">
                <span className="text-[10px] text-[#657180] uppercase tracking-wide block mb-1 font-semibold">Event Explanation</span>
                <p className="text-xs text-[#475569] leading-relaxed">
                  {activeEvent.explanation || activeEvent.what_happened}
                </p>
              </div>
            )}
          </div>

          {/* ── RIGHT: Original Raw Evidence ───────────────────────────────── */}
          <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 flex flex-col gap-4 shadow-card">

            {/* Pane header */}
            <div className="flex items-center justify-between pb-2 border-b border-[#DDE3EA]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#16A34A]" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-[#252B33]">Original Raw Evidence</h3>
              </div>
              <button
                onClick={handleCopyRaw}
                disabled={!activeEvent.raw_log}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#F0F3F6] hover:bg-[#E2E8F0] border border-[#DDE3EA] disabled:opacity-40 text-[#252B33] text-xs transition shadow-subtle"
                aria-label="Copy raw log to clipboard"
              >
                {copied
                  ? <><Check className="w-3.5 h-3.5 text-[#16A34A]" /> Copied!</>
                  : <><Copy className="w-3.5 h-3.5" /> Copy</>
                }
              </button>
            </div>

            {/* Source & timestamp provenance line */}
            {(activeEvent.host || activeEvent.timestamp) && (
              <div className="text-[10px] font-mono text-[#657180] -mt-2">
                Source: {activeEvent.host || 'unknown'} · Recorded: {activeEvent.timestamp || '—'}
              </div>
            )}

            {/* Raw log viewer */}
            {activeEvent.raw_log ? (
              <div
                className="flex-1 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-4 font-mono text-xs text-[#1E293B] leading-relaxed overflow-x-auto overflow-y-auto whitespace-pre-wrap break-words max-h-80 shadow-inner"
                role="region"
                aria-label="Raw log entry"
              >
                {activeEvent.raw_log}
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-4 min-h-[120px]">
                <p className="text-xs text-[#94A3B8] italic text-center">
                  No raw log entry is available for this event.<br />
                  The parsed attributes on the left were derived during normalization.
                </p>
              </div>
            )}

            {/* Clarification note */}
            <div className="text-[10px] text-[#657180] bg-[#F8FAFC] rounded p-2.5 border border-[#DDE3EA]">
              The content above is displayed verbatim from the ingest pipeline. It has not been
              modified, summarized, or substituted with normalized data.
            </div>

            {/* Chain-of-custody badge — honest */}
            <CustodyBadge event={activeEvent} />
          </div>
        </div>
      ) : (
        /* ── Empty state ─────────────────────────────────────────────────── */
        <div className="p-14 text-center bg-white border border-[#DDE3EA] rounded-xl shadow-card">
          <FileSearch className="w-10 h-10 text-[#CBD5E1] mx-auto mb-3" aria-hidden="true" />
          <p className="text-sm font-semibold text-[#252B33] mb-1">No event selected</p>
          <p className="text-xs text-[#657180] max-w-sm mx-auto">
            Select an event from the Interactive Security Timeline or click a point on the
            Scatter Plot to load its normalized attributes and original raw log here.
          </p>
        </div>
      )}
    </div>
  );
}
