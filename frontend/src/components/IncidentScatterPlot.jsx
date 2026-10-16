import React, { useState, useMemo, useRef, useCallback } from 'react';
import {
  ResponsiveContainer, ScatterChart, Scatter,
  XAxis, YAxis, ZAxis, Tooltip, CartesianGrid, ReferenceLine
} from 'recharts';
import { Filter, Search, Info, Eye, ZoomIn } from 'lucide-react';

// ─── Category colour palette (Wazuh enterprise theme) ─────────────────────────
const CAT_PALETTE = {
  AUTHENTICATION: { fill: '#1677C8', label: 'Authentication', shape: 'circle'   },
  SYSTEM:         { fill: '#DD6B20', label: 'System',         shape: 'square'   },
  NETWORK:        { fill: '#6B46C1', label: 'Network',        shape: 'triangle' },
};
const FALLBACK_FILL = '#657180';

function catFill(cat) { return CAT_PALETTE[cat]?.fill ?? FALLBACK_FILL; }

// ─── Plain-language event labels ──────────────────────────────────────────────
const FRIENDLY_LABEL = {
  brute_force_attempt:  'Repeated login failures',
  brute_force_success:  'Login after repeated failures',
  login_off_hours:      'Unusual login time',
  privilege_escalation: 'Permission change',
  lateral_movement:     'Unexpected system access',
  data_exfiltration:    'Large data transfer',
  suspicious_process:   'Unusual process started',
  port_scan:            'Network scan detected',
  suspicious_outbound:  'Unusual outbound connection',
  firewall_block:       'Blocked connection',
  service_restart:      'Service restarted',
  config_change:        'Config change',
  account_created:      'New account created',
  account_locked:       'Account locked out',
  login_failure:        'Failed login attempt',
  auth_failure:         'Failed login attempt',
  login_success:        'Successful login',
};
function friendlyLabel(event_type) {
  if (!event_type) return 'Security event';
  const key = event_type.toLowerCase().replace(/\s+/g, '_');
  return FRIENDLY_LABEL[key] || event_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ─── Severity band helpers ─────────────────────────────────────────────────────
function sevColor(score) {
  if (score >= 7.0) return 'text-[#C53030]';
  if (score >= 4.5) return 'text-[#DD6B20]';
  return 'text-[#1677C8]';
}
function sevLabel(score) {
  if (score >= 7.0) return 'High Risk';
  if (score >= 4.5) return 'Needs Attention';
  return 'Informational';
}

// ─── Custom rich Tooltip (Wazuh theme) ─────────────────────────────────────────
function ScatterTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  const score = Number(d.yValue ?? d.severity_score ?? 0);
  const explanation = d.explanation || d.what_happened || d.description;

  return (
    <div className="bg-white border border-[#DDE3EA] rounded-xl shadow-xl p-3.5 text-xs max-w-[280px] pointer-events-none text-[#252B33]">
      {/* Header */}
      <div className="flex items-start justify-between gap-2 border-b border-[#DDE3EA] pb-2 mb-2">
        <span className="font-semibold text-[#252B33] leading-snug">{friendlyLabel(d.event_type)}</span>
        <span className={`shrink-0 font-mono font-bold px-1.5 py-0.5 rounded text-[10px] ${
          score >= 7.0 ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]' :
          score >= 4.5 ? 'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]' :
          'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]'
        }`}>
          {score.toFixed(1)}
        </span>
      </div>

      <div className="space-y-1 text-[#475569]">
        <div className="flex gap-1.5">
          <span className="text-[#657180] w-16 shrink-0">Time</span>
          <span className="font-mono text-[#252B33] text-[11px]">{d.timeLabel}</span>
        </div>
        <div className="flex gap-1.5">
          <span className="text-[#657180] w-16 shrink-0">Category</span>
          <span className="font-medium" style={{ color: catFill(d.category) }}>{d.category}</span>
        </div>
        <div className="flex gap-1.5">
          <span className="text-[#657180] w-16 shrink-0">Severity</span>
          <span className={`font-mono font-semibold ${sevColor(score)}`}>
            {score.toFixed(1)} / 10 — {sevLabel(score)}
          </span>
        </div>
        {d.user && (
          <div className="flex gap-1.5">
            <span className="text-[#657180] w-16 shrink-0">User</span>
            <span className="font-mono text-[#252B33]">{d.user}</span>
          </div>
        )}
        {d.source_ip && (
          <div className="flex gap-1.5">
            <span className="text-[#657180] w-16 shrink-0">Source IP</span>
            <span className="font-mono text-[#252B33]">{d.source_ip}</span>
          </div>
        )}
      </div>

      {explanation ? (
        <div className="mt-2 pt-2 border-t border-[#DDE3EA]">
          <p className="text-[10px] text-[#657180] uppercase tracking-wider mb-0.5 font-semibold">Why flagged</p>
          <p className="text-[11px] text-[#475569] leading-relaxed">{explanation}</p>
        </div>
      ) : (
        <div className="mt-2 pt-2 border-t border-[#DDE3EA]">
          <p className="text-[11px] text-[#94A3B8] italic">No explanation available for this event.</p>
        </div>
      )}

      <div className="mt-2 text-[10px] text-[#1677C8] font-mono text-center font-medium">
        Click to inspect evidence →
      </div>
    </div>
  );
}

// ─── Custom dot renderer — highlights the selected point ─────────────────────
function CustomDot(props) {
  const { cx, cy, payload, selectedId, onSelect } = props;
  const isSelected = payload?.id && payload.id === selectedId;
  const fill = catFill(payload?.category);
  const r = isSelected ? 9 : 6;

  return (
    <circle
      cx={cx}
      cy={cy}
      r={r}
      fill={isSelected ? '#fff' : fill}
      stroke={fill}
      strokeWidth={isSelected ? 3 : 1.5}
      style={{ cursor: 'pointer', transition: 'r 0.12s, fill 0.12s' }}
      onClick={() => onSelect(payload)}
      role="button"
      aria-label={`${friendlyLabel(payload?.event_type)}, severity ${(payload?.yValue ?? 0).toFixed(1)}`}
      tabIndex={0}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(payload); } }}
    />
  );
}

// ─── Info tooltip popup ──────────────────────────────────────────────────────
function InfoPopup({ open, onClose }) {
  if (!open) return null;
  return (
    <div className="absolute top-8 right-0 z-50 bg-white border border-[#DDE3EA] rounded-xl p-3.5 shadow-xl w-72 text-xs text-[#475569] leading-relaxed">
      <button onClick={onClose} className="float-right text-[#94A3B8] hover:text-[#252B33] ml-2" aria-label="Close info">✕</button>
      <p className="font-semibold text-[#252B33] mb-1.5">How to read this chart</p>
      <p><strong className="text-[#1677C8]">Colors</strong> represent event categories — what type of activity occurred.</p>
      <ul className="mt-1.5 space-y-0.5 pl-2">
        {Object.values(CAT_PALETTE).map(({ fill, label }) => (
          <li key={label} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: fill }} />
            {label}
          </li>
        ))}
      </ul>
      <p className="mt-2"><strong className="text-[#252B33]">Vertical position</strong> (Y-axis) shows severity — higher points are higher concern.</p>
      <p className="mt-1.5 text-[#657180] text-[10px]">Severity is a prioritization score, not proof of malicious activity. All alerts are investigation leads requiring human review.</p>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function IncidentScatterPlot({ events, onInspectEvent }) {
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [minSeverity, setMinSeverity] = useState(1.0);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPointId, setSelectedPointId] = useState(null);
  const [showInfo, setShowInfo] = useState(false);

  // ── Prepare data ──────────────────────────────────────────────────────────
  const { authPoints, systemPoints, networkPoints, totalFiltered } = useMemo(() => {
    if (!events) return { authPoints: [], systemPoints: [], networkPoints: [], totalFiltered: 0 };

    const sorted = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const enriched = sorted.map((e, index) => {
      const dt = new Date(e.timestamp);
      return {
        ...e,
        xIndex: index,
        timeLabel: isNaN(dt.getTime()) ? '—' : dt.toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        dateLabel: isNaN(dt.getTime()) ? '—' : dt.toISOString().split('T')[0],
        yValue: Number(e.severity_score || 1.0),
      };
    });

    const filtered = enriched.filter(item => {
      if (selectedCategory !== 'ALL' && item.category !== selectedCategory) return false;
      if (item.yValue < minSeverity) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !(item.user      && item.user.toLowerCase().includes(q)) &&
          !(item.host      && item.host.toLowerCase().includes(q)) &&
          !(item.event_type && item.event_type.toLowerCase().includes(q)) &&
          !(item.source_ip && item.source_ip.toLowerCase().includes(q)) &&
          !(item.dest_host && item.dest_host.toLowerCase().includes(q))
        ) return false;
      }
      return true;
    });

    return {
      authPoints:    filtered.filter(p => p.category === 'AUTHENTICATION'),
      systemPoints:  filtered.filter(p => p.category === 'SYSTEM'),
      networkPoints: filtered.filter(p => p.category === 'NETWORK'),
      totalFiltered: filtered.length,
    };
  }, [events, selectedCategory, minSeverity, searchQuery]);

  // ── Handle point selection → navigate to inspector ────────────────────────
  const handleSelect = useCallback((node) => {
    setSelectedPointId(node.id);
    onInspectEvent(node); // wires into App.jsx → setInspectingEvent + navigate to inspector tab
  }, [onInspectEvent]);

  // Shared dot renderer factory
  const makeDot = (props) => (
    <CustomDot {...props} selectedId={selectedPointId} onSelect={handleSelect} />
  );

  // X-axis tick formatter — show HH:MM:SS from actual event index
  const allSorted = useMemo(() =>
    [...(events || [])].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)),
    [events]
  );
  const xTickFmt = (val) => {
    const ev = allSorted[val];
    if (!ev) return '';
    const d = new Date(ev.timestamp);
    return isNaN(d.getTime()) ? '' : d.toISOString().substring(11, 16); // HH:MM
  };

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">

      {/* ── Header & Controls ─────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-[#252B33] flex items-center gap-2">
              <ZoomIn className="w-4 h-4 text-[#1677C8]" aria-hidden="true" />
              Single Event Correlation Scatter Plot
            </h2>
            <p className="text-xs text-[#657180] mt-0.5 max-w-xl">
              Each point represents an event. The X-axis shows when it occurred, and the Y-axis shows
              its severity from 1.0 to 10.0. Point colors identify the event category. Select a point
              to inspect its evidence.
            </p>
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {/* Category selector */}
            <div className="flex items-center rounded-md bg-[#F0F3F6] border border-[#DDE3EA] p-0.5 text-xs shadow-subtle" role="group" aria-label="Category filter">
              {['ALL', 'AUTHENTICATION', 'SYSTEM', 'NETWORK'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition ${
                    selectedCategory === cat ? 'bg-[#1677C8] text-white shadow-sm' : 'text-[#475569] hover:text-[#252B33]'
                  }`}
                  aria-pressed={selectedCategory === cat}
                >
                  {cat === 'AUTHENTICATION' ? 'Auth' : cat === 'SYSTEM' ? 'Sys' : cat === 'NETWORK' ? 'Net' : 'All'}
                </button>
              ))}
            </div>

            {/* Severity slider */}
            <div className="flex items-center gap-2 bg-[#F0F3F6] border border-[#DDE3EA] px-3 py-1 rounded-md text-xs shadow-subtle">
              <span className="text-[#657180] text-[11px] whitespace-nowrap">Min severity:</span>
              <input
                type="range" min="1.0" max="9.0" step="0.5"
                value={minSeverity}
                onChange={e => setMinSeverity(parseFloat(e.target.value))}
                className="w-20 accent-[#1677C8] cursor-pointer"
                aria-label={`Minimum severity: ${minSeverity}`}
              />
              <span className="font-mono text-[#1677C8] font-bold text-xs w-6 text-right">{minSeverity.toFixed(1)}</span>
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94A3B8]" aria-hidden="true" />
              <input
                type="text"
                placeholder="User, host, IP…"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-3 py-1 text-xs text-[#252B33] placeholder-[#94A3B8] focus:outline-none focus:border-[#1677C8] w-36 shadow-subtle"
                aria-label="Search events"
              />
            </div>
          </div>
        </div>

        {/* Category legend + info icon */}
        <div className="mt-3 pt-3 border-t border-[#DDE3EA] flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-[#657180]">
          {Object.values(CAT_PALETTE).map(({ fill, label }) => (
            <span key={label} className="flex items-center gap-1.5 font-medium">
              <span className="w-2.5 h-2.5 rounded-full inline-block shrink-0" style={{ background: fill }} aria-hidden="true" />
              {label}
            </span>
          ))}

          <div className="ml-auto flex items-center gap-3">
            {(selectedCategory !== 'ALL' || minSeverity > 1.0 || searchQuery) && (
              <button
                onClick={() => { setSelectedCategory('ALL'); setMinSeverity(1.0); setSearchQuery(''); }}
                className="text-[#1677C8] text-[11px] hover:underline font-medium"
              >
                Reset filters
              </button>
            )}
            <span className="font-mono text-[11px]">
              Showing <strong className="text-[#252B33]">{totalFiltered}</strong> of {events?.length || 0} events
            </span>
            <div className="relative">
              <button
                onClick={() => setShowInfo(v => !v)}
                className="p-1 rounded text-[#657180] hover:text-[#1677C8] transition"
                aria-label="How to read this chart"
                aria-expanded={showInfo}
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <InfoPopup open={showInfo} onClose={() => setShowInfo(false)} />
            </div>
          </div>
        </div>
      </div>

      {/* ── Chart Card ────────────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">

        {/* Selected point banner */}
        {selectedPointId && (
          <div className="mb-3 flex items-center justify-between px-3 py-2 rounded-md bg-[#EAF3FB] border border-[#BFDBFE] text-xs text-[#1677C8]">
            <span className="flex items-center gap-1.5 font-medium">
              <Eye className="w-3.5 h-3.5" />
              Point selected — evidence loaded in the Forensic Evidence Inspector
            </span>
            <button onClick={() => setSelectedPointId(null)} className="text-[#657180] hover:text-[#252B33]" aria-label="Clear selection">✕</button>
          </div>
        )}

        {totalFiltered === 0 ? (
          <div className="flex flex-col items-center justify-center h-60 gap-3 text-center text-[#657180]">
            <Filter className="w-8 h-8 text-[#CBD5E1]" aria-hidden="true" />
            <p className="text-sm font-semibold text-[#252B33]">No events match the current filters</p>
            <p className="text-xs max-w-xs">Try lowering the minimum severity or clearing the search and category filter.</p>
          </div>
        ) : (
          <div className="h-[440px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 20, right: 30, bottom: 40, left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#EDF2F7" vertical={false} />

                {/* X-axis */}
                <XAxis
                  dataKey="xIndex"
                  name="Event Timeline"
                  stroke="#657180"
                  fontSize={10}
                  tickLine={false}
                  tickFormatter={xTickFmt}
                  label={{
                    value: 'Event Timeline',
                    position: 'insideBottom',
                    offset: -24,
                    fill: '#657180',
                    fontSize: 11,
                  }}
                />

                {/* Y-axis */}
                <YAxis
                  dataKey="yValue"
                  name="Severity (1.0–10.0)"
                  domain={[0, 10]}
                  ticks={[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
                  stroke="#657180"
                  fontSize={10}
                  tickLine={false}
                  label={{
                    value: 'Severity (1.0–10.0)',
                    angle: -90,
                    position: 'insideLeft',
                    offset: -6,
                    fill: '#657180',
                    fontSize: 11,
                  }}
                />

                <ZAxis range={[55, 55]} />

                {/* Reference lines for severity bands */}
                <ReferenceLine y={7.0} stroke="#C5303040" strokeDasharray="4 3" label={{ value: 'High Risk', fill: '#C53030', fontSize: 9, position: 'right' }} />
                <ReferenceLine y={4.5} stroke="#DD6B2040" strokeDasharray="4 3" label={{ value: 'Attention', fill: '#DD6B20', fontSize: 9, position: 'right' }} />

                <Tooltip content={<ScatterTooltip />} cursor={{ strokeDasharray: '3 3', stroke: '#CBD5E1' }} />

                {/* Authentication series */}
                <Scatter
                  name="Authentication"
                  data={authPoints}
                  fill={CAT_PALETTE.AUTHENTICATION.fill}
                  shape={makeDot}
                  cursor="pointer"
                  isAnimationActive={false}
                />

                {/* System series */}
                <Scatter
                  name="System"
                  data={systemPoints}
                  fill={CAT_PALETTE.SYSTEM.fill}
                  shape={makeDot}
                  cursor="pointer"
                  isAnimationActive={false}
                />

                {/* Network series */}
                <Scatter
                  name="Network"
                  data={networkPoints}
                  fill={CAT_PALETTE.NETWORK.fill}
                  shape={makeDot}
                  cursor="pointer"
                  isAnimationActive={false}
                />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Footer note */}
        <div className="mt-3 pt-2 border-t border-[#DDE3EA] flex flex-wrap items-center justify-between gap-2 text-[11px] text-[#657180]">
          <span className="flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-[#1677C8]" aria-hidden="true" />
            Colors identify event category. Higher vertical position = higher severity. Click any point to load evidence.
          </span>
          <span className="font-mono">Y-axis: 1.0 (benign) → 10.0 (high concern)</span>
        </div>
      </div>
    </div>
  );
}
