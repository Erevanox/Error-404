import React, { useState, useMemo, useRef, useCallback } from 'react';
import {
  ResponsiveContainer, ScatterChart, Scatter,
  BarChart, Bar,
  XAxis, YAxis, ZAxis, Tooltip, CartesianGrid, ReferenceLine, Legend
} from 'recharts';
import {
  Filter, Search, Info, Eye, ZoomIn,
  BarChart2, Table as TableIcon, ScatterChart as ScatterIcon,
  ChevronDown, ChevronRight, Copy, Check, ExternalLink, Flame, ShieldAlert,
  ArrowUpDown, Activity, Clock, Shield, Database, ChevronLeft
} from 'lucide-react';

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
function sevBadgeClass(score) {
  if (score >= 7.0) return 'bg-[#FDE8E8] text-[#C53030] border-[#F8B4B4]';
  if (score >= 4.5) return 'bg-[#FEEBC8] text-[#DD6B20] border-[#FBD38D]';
  return 'bg-[#EAF3FB] text-[#1677C8] border-[#BFDBFE]';
}
function sevLabel(score) {
  if (score >= 7.0) return 'High Risk';
  if (score >= 4.5) return 'Needs Attention';
  return 'Informational';
}

// ─── Custom rich Tooltip for Scatter Plot ────────────────────────────────────
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
        <span className={`shrink-0 font-mono font-bold px-1.5 py-0.5 rounded text-[10px] border ${sevBadgeClass(score)}`}>
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

// ─── Custom Tooltip for Histogram ─────────────────────────────────────────────
function HistogramTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const data = payload[0].payload;
  return (
    <div className="bg-white border border-[#DDE3EA] rounded-xl shadow-xl p-3 text-xs min-w-[200px] pointer-events-none text-[#252B33]">
      <div className="flex items-center justify-between border-b border-[#DDE3EA] pb-1.5 mb-2">
        <span className="font-bold text-[#0F172A] font-mono">{data.time} ({data.date})</span>
        <span className="font-semibold text-xs text-[#059669] bg-[#ECFDF5] px-1.5 py-0.5 rounded border border-[#A7F3D0]">
          {data.total} logs
        </span>
      </div>
      <div className="space-y-1.5 text-[11px]">
        <div className="flex justify-between items-center text-[#1677C8]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#1677C8]" />
            Authentication:
          </span>
          <span className="font-mono font-bold">{data.AUTHENTICATION}</span>
        </div>
        <div className="flex justify-between items-center text-[#DD6B20]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#DD6B20]" />
            System:
          </span>
          <span className="font-mono font-bold">{data.SYSTEM}</span>
        </div>
        <div className="flex justify-between items-center text-[#6B46C1]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#6B46C1]" />
            Network:
          </span>
          <span className="font-mono font-bold">{data.NETWORK}</span>
        </div>
        {data.highSeverity > 0 && (
          <div className="pt-1.5 mt-1 border-t border-[#F1F5F9] flex justify-between items-center text-[#DC2626] font-semibold">
            <span className="flex items-center gap-1">
              <Flame className="w-3 h-3 text-[#DC2626]" />
              High Risk (≥ 7.0):
            </span>
            <span className="font-mono">{data.highSeverity}</span>
          </div>
        )}
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
  const [viewMode, setViewMode] = useState('scatter'); // 'scatter' | 'histogram' | 'table'
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [minSeverity, setMinSeverity] = useState(1.0);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPointId, setSelectedPointId] = useState(null);
  const [showInfo, setShowInfo] = useState(false);

  // Table-specific states
  const [expandedRows, setExpandedRows] = useState({});
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [copiedId, setCopiedId] = useState(null);
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('asc'); // 'asc' | 'desc'

  // ── Prepare and filter data ────────────────────────────────────────────────
  const { authPoints, systemPoints, networkPoints, totalFiltered, allFiltered } = useMemo(() => {
    if (!events) return { authPoints: [], systemPoints: [], networkPoints: [], totalFiltered: 0, allFiltered: [] };

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
      allFiltered:   filtered,
    };
  }, [events, selectedCategory, minSeverity, searchQuery]);

  // ── Prepare Histogram Data ────────────────────────────────────────────────
  const { histogramData, histogramStats } = useMemo(() => {
    if (!allFiltered || allFiltered.length === 0) return { histogramData: [], histogramStats: null };

    const chrono = [...allFiltered].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const firstTime = new Date(chrono[0].timestamp).getTime();
    const lastTime = new Date(chrono[chrono.length - 1].timestamp).getTime();
    const spanMs = Math.max(lastTime - firstTime, 60000);

    const numBuckets = Math.min(20, Math.max(8, Math.ceil(chrono.length / 12)));
    const bucketDuration = spanMs / numBuckets;

    const buckets = Array.from({ length: numBuckets }, (_, i) => {
      const bStart = firstTime + i * bucketDuration;
      const bEnd = bStart + bucketDuration;
      const startDt = new Date(bStart);
      return {
        start: bStart,
        end: bEnd,
        time: isNaN(startDt.getTime()) ? `B${i+1}` : startDt.toISOString().substring(11, 16),
        date: isNaN(startDt.getTime()) ? '' : startDt.toISOString().substring(0, 10),
        AUTHENTICATION: 0,
        SYSTEM: 0,
        NETWORK: 0,
        highSeverity: 0,
        total: 0,
      };
    });

    chrono.forEach(ev => {
      const t = new Date(ev.timestamp).getTime();
      let bIdx = Math.floor((t - firstTime) / bucketDuration);
      if (bIdx >= numBuckets) bIdx = numBuckets - 1;
      if (bIdx < 0) bIdx = 0;

      const bucket = buckets[bIdx];
      bucket.total += 1;
      if (ev.category === 'AUTHENTICATION') bucket.AUTHENTICATION += 1;
      else if (ev.category === 'SYSTEM') bucket.SYSTEM += 1;
      else if (ev.category === 'NETWORK') bucket.NETWORK += 1;

      if (ev.yValue >= 7.0) bucket.highSeverity += 1;
    });

    const maxVolume = Math.max(...buckets.map(b => b.total), 1);
    const totalHighRisk = buckets.reduce((acc, b) => acc + b.highSeverity, 0);

    return {
      histogramData: buckets,
      histogramStats: {
        maxVolume,
        totalHighRisk,
        bucketCount: numBuckets,
        spanMinutes: Math.round(spanMs / 60000),
      }
    };
  }, [allFiltered]);

  // ── Prepare Table Data & Sorting ──────────────────────────────────────────
  const sortedTableData = useMemo(() => {
    return [...allFiltered].sort((a, b) => {
      let comparison = 0;
      if (sortField === 'timestamp') {
        comparison = new Date(a.timestamp) - new Date(b.timestamp);
      } else if (sortField === 'severity') {
        comparison = a.yValue - b.yValue;
      } else if (sortField === 'category') {
        comparison = (a.category || '').localeCompare(b.category || '');
      } else if (sortField === 'user') {
        comparison = (a.user || '').localeCompare(b.user || '');
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [allFiltered, sortField, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sortedTableData.length / pageSize));
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedTableData.slice(start, start + pageSize);
  }, [sortedTableData, currentPage, pageSize]);

  const toggleRowExpansion = (id) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const copyEventJson = (event) => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopiedId(event.id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // ── Handle point selection → navigate to inspector ────────────────────────
  const handleSelect = useCallback((node) => {
    setSelectedPointId(node.id);
    if (onInspectEvent) onInspectEvent(node);
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
    return isNaN(d.getTime()) ? '' : d.toISOString().substring(11, 16);
  };

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">

      {/* ── Header & View Switcher Bar ───────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] text-[#059669]">
                <Activity className="w-4 h-4 text-[#10B981]" />
              </span>
              <h2 className="text-sm font-bold text-[#0F172A] tracking-tight">
                Log Explorer &amp; Correlation Workspace
              </h2>
            </div>
            <p className="text-xs text-[#64748B] mt-1 max-w-xl">
              Inspect raw and correlated telemetry across time distributions, surge histograms, and detailed SIEM event records.
            </p>
          </div>

          {/* View Switcher Controls */}
          <div className="flex items-center rounded-xl bg-[#F1F5F9] border border-[#CBD5E1] p-1 shadow-subtle self-start lg:self-auto">
            <button
              onClick={() => setViewMode('scatter')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                viewMode === 'scatter'
                  ? 'bg-white text-[#0F172A] shadow-sm border border-[#E2E8F0]'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              <ScatterIcon className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Scatter Plot</span>
            </button>

            <button
              onClick={() => setViewMode('histogram')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                viewMode === 'histogram'
                  ? 'bg-white text-[#0F172A] shadow-sm border border-[#E2E8F0]'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              <BarChart2 className="w-3.5 h-3.5 text-[#2563EB]" />
              <span>Event Volume</span>
            </button>

            <button
              onClick={() => setViewMode('table')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                viewMode === 'table'
                  ? 'bg-white text-[#0F172A] shadow-sm border border-[#E2E8F0]'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5 text-[#7C3AED]" />
              <span>Log Table</span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-[#E2E8F0] text-[#334155] font-bold">
                {totalFiltered}
              </span>
            </button>
          </div>
        </div>

        {/* Universal Filter Controls */}
        <div className="mt-4 pt-3 border-t border-[#E2E8F0] flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {/* Category selector */}
            <div className="flex items-center rounded-lg bg-[#F8FAFC] border border-[#CBD5E1] p-0.5 text-xs shadow-subtle">
              {['ALL', 'AUTHENTICATION', 'SYSTEM', 'NETWORK'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition ${
                    selectedCategory === cat
                      ? 'bg-[#10B981] text-white shadow-sm font-semibold'
                      : 'text-[#64748B] hover:text-[#0F172A]'
                  }`}
                >
                  {cat === 'AUTHENTICATION' ? 'Auth' : cat === 'SYSTEM' ? 'Sys' : cat === 'NETWORK' ? 'Net' : 'All Categories'}
                </button>
              ))}
            </div>

            {/* Severity slider */}
            <div className="flex items-center gap-2 bg-[#F8FAFC] border border-[#CBD5E1] px-3 py-1 rounded-lg text-xs shadow-subtle">
              <span className="text-[#64748B] text-[11px] whitespace-nowrap">Min severity:</span>
              <input
                type="range" min="1.0" max="9.0" step="0.5"
                value={minSeverity}
                onChange={e => setMinSeverity(parseFloat(e.target.value))}
                className="w-20 accent-[#10B981] cursor-pointer"
              />
              <span className="font-mono text-[#059669] font-bold text-xs w-6 text-right">
                {minSeverity.toFixed(1)}
              </span>
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94A3B8]" />
              <input
                type="text"
                placeholder="Search user, host, IP, event…"
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setCurrentPage(1); }}
                className="bg-white border border-[#CBD5E1] rounded-lg pl-8 pr-3 py-1 text-xs text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:ring-1 focus:ring-[#10B981] focus:border-[#10B981] w-48 shadow-subtle transition"
              />
            </div>
          </div>

          {/* Filter status & Reset */}
          <div className="flex items-center gap-3 text-xs text-[#64748B]">
            {(selectedCategory !== 'ALL' || minSeverity > 1.0 || searchQuery) && (
              <button
                onClick={() => { setSelectedCategory('ALL'); setMinSeverity(1.0); setSearchQuery(''); setCurrentPage(1); }}
                className="text-[#10B981] hover:text-[#059669] text-[11px] underline font-medium"
              >
                Reset filters
              </button>
            )}
            <span className="font-mono text-[11px]">
              Showing <strong className="text-[#0F172A]">{totalFiltered}</strong> of {events?.length || 0} events
            </span>
            <div className="relative">
              <button
                onClick={() => setShowInfo(v => !v)}
                className="p-1 rounded text-[#64748B] hover:text-[#0F172A] transition"
                title="Help info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <InfoPopup open={showInfo} onClose={() => setShowInfo(false)} />
            </div>
          </div>
        </div>
      </div>

      {/* ── Main Dynamic View Container ──────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">

        {/* Selected point alert notification */}
        {selectedPointId && (
          <div className="mb-3 flex items-center justify-between px-3 py-2 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] text-xs text-[#059669]">
            <span className="flex items-center gap-1.5 font-medium">
              <Eye className="w-3.5 h-3.5" />
              Event selected — loaded in the Forensic Evidence Inspector
            </span>
            <button onClick={() => setSelectedPointId(null)} className="text-[#059669] hover:text-[#047857]" aria-label="Clear selection">✕</button>
          </div>
        )}

        {totalFiltered === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 gap-3 text-center text-[#64748B]">
            <Filter className="w-8 h-8 text-[#CBD5E1]" />
            <p className="text-sm font-semibold text-[#0F172A]">No events match the current filters</p>
            <p className="text-xs max-w-xs text-[#64748B]">Try lowering the minimum severity slider or clearing the search query.</p>
          </div>
        ) : (
          <>
            {/* ── VIEW 1: SCATTER PLOT ─────────────────────────────────────── */}
            {viewMode === 'scatter' && (
              <div>
                <div className="flex items-center justify-between mb-3 text-xs text-[#64748B]">
                  <div className="flex items-center gap-4">
                    {Object.values(CAT_PALETTE).map(({ fill, label }) => (
                      <span key={label} className="flex items-center gap-1.5 font-medium">
                        <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: fill }} />
                        {label}
                      </span>
                    ))}
                  </div>
                  <span className="font-mono text-[11px] text-[#94A3B8]">
                    Y: Severity (1.0 - 10.0) • X: Event Sequence
                  </span>
                </div>

                <div className="h-[430px] w-full">
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

                      <ReferenceLine y={7.0} stroke="#C5303040" strokeDasharray="4 3" label={{ value: 'High Risk', fill: '#C53030', fontSize: 9, position: 'right' }} />
                      <ReferenceLine y={4.5} stroke="#DD6B2040" strokeDasharray="4 3" label={{ value: 'Attention', fill: '#DD6B20', fontSize: 9, position: 'right' }} />

                      <Tooltip content={<ScatterTooltip />} cursor={{ strokeDasharray: '3 3', stroke: '#CBD5E1' }} />

                      <Scatter
                        name="Authentication"
                        data={authPoints}
                        fill={CAT_PALETTE.AUTHENTICATION.fill}
                        shape={makeDot}
                        cursor="pointer"
                        isAnimationActive={false}
                      />
                      <Scatter
                        name="System"
                        data={systemPoints}
                        fill={CAT_PALETTE.SYSTEM.fill}
                        shape={makeDot}
                        cursor="pointer"
                        isAnimationActive={false}
                      />
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

                <div className="mt-3 pt-2 border-t border-[#E2E8F0] flex flex-wrap items-center justify-between gap-2 text-[11px] text-[#64748B]">
                  <span className="flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-[#10B981]" />
                    Click any point to inspect full cryptographic evidence in the Forensic Evidence Inspector.
                  </span>
                  <span className="font-mono">1.0 (Benign) → 10.0 (High Concern)</span>
                </div>
              </div>
            )}

            {/* ── VIEW 2: EVENT VOLUME HISTOGRAM ────────────────────────────── */}
            {viewMode === 'histogram' && (
              <div>
                {/* Metric Summary Cards */}
                {histogramStats && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                    <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                      <span className="text-[10px] font-mono uppercase text-[#64748B] block font-semibold">Total Logs Binned</span>
                      <strong className="text-base text-[#0F172A] font-mono">{totalFiltered}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                      <span className="text-[10px] font-mono uppercase text-[#64748B] block font-semibold">Peak Burst Volume</span>
                      <strong className="text-base text-[#2563EB] font-mono">{histogramStats.maxVolume} <span className="text-xs font-normal text-[#64748B]">events/bin</span></strong>
                    </div>
                    <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                      <span className="text-[10px] font-mono uppercase text-[#64748B] block font-semibold">High Risk Events</span>
                      <strong className="text-base text-[#DC2626] font-mono">{histogramStats.totalHighRisk}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                      <span className="text-[10px] font-mono uppercase text-[#64748B] block font-semibold">Investigation Span</span>
                      <strong className="text-base text-[#059669] font-mono">{histogramStats.spanMinutes} <span className="text-xs font-normal text-[#64748B]">minutes</span></strong>
                    </div>
                  </div>
                )}

                {/* Histogram Bar Chart */}
                <div className="h-[380px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={histogramData} margin={{ top: 20, right: 30, bottom: 40, left: 10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#EDF2F7" vertical={false} />
                      <XAxis
                        dataKey="time"
                        stroke="#657180"
                        fontSize={10}
                        tickLine={false}
                        label={{
                          value: 'Time Intervals (HH:MM UTC)',
                          position: 'insideBottom',
                          offset: -20,
                          fill: '#657180',
                          fontSize: 11,
                        }}
                      />
                      <YAxis
                        stroke="#657180"
                        fontSize={10}
                        tickLine={false}
                        label={{
                          value: 'Event Count',
                          angle: -90,
                          position: 'insideLeft',
                          offset: -2,
                          fill: '#657180',
                          fontSize: 11,
                        }}
                      />
                      <Tooltip content={<HistogramTooltip />} />
                      <Legend
                        verticalAlign="top"
                        align="right"
                        iconType="circle"
                        wrapperStyle={{ fontSize: '11px', paddingBottom: '10px' }}
                      />
                      <Bar dataKey="AUTHENTICATION" name="Authentication" stackId="stack" fill="#1677C8" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="SYSTEM" name="System" stackId="stack" fill="#DD6B20" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="NETWORK" name="Network" stackId="stack" fill="#6B46C1" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="mt-3 pt-2 border-t border-[#E2E8F0] flex items-center justify-between text-[11px] text-[#64748B]">
                  <span>Stacked bars represent event volume composition per time interval. Spikes indicate potential brute force or exfiltration bursts.</span>
                </div>
              </div>
            )}

            {/* ── VIEW 3: FULL LOG TABLE ───────────────────────────────────── */}
            {viewMode === 'table' && (
              <div className="space-y-3">
                {/* Table Header Bar */}
                <div className="flex items-center justify-between text-xs text-[#64748B] pb-1">
                  <span className="font-mono text-[11px]">
                    Displaying <strong>{paginatedLogs.length}</strong> records (Page {currentPage} of {totalPages})
                  </span>

                  <div className="flex items-center gap-2">
                    <span className="text-[11px]">Rows per page:</span>
                    <select
                      value={pageSize}
                      onChange={e => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                      className="bg-white border border-[#CBD5E1] rounded px-2 py-0.5 text-xs text-[#0F172A] focus:outline-none"
                    >
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                    </select>
                  </div>
                </div>

                {/* Table */}
                <div className="overflow-x-auto border border-[#E2E8F0] rounded-xl shadow-subtle">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-[#F8FAFC] text-[#475569] font-mono text-[10px] uppercase border-b border-[#E2E8F0] select-none">
                      <tr>
                        <th className="py-2.5 px-3 w-8"></th>
                        <th
                          onClick={() => handleSort('timestamp')}
                          className="py-2.5 px-3 cursor-pointer hover:text-[#0F172A] transition"
                        >
                          <div className="flex items-center gap-1">
                            <span>Timestamp</span>
                            <ArrowUpDown className="w-3 h-3 text-[#94A3B8]" />
                          </div>
                        </th>
                        <th
                          onClick={() => handleSort('severity')}
                          className="py-2.5 px-3 cursor-pointer hover:text-[#0F172A] transition"
                        >
                          <div className="flex items-center gap-1">
                            <span>Severity</span>
                            <ArrowUpDown className="w-3 h-3 text-[#94A3B8]" />
                          </div>
                        </th>
                        <th
                          onClick={() => handleSort('category')}
                          className="py-2.5 px-3 cursor-pointer hover:text-[#0F172A] transition"
                        >
                          <div className="flex items-center gap-1">
                            <span>Category</span>
                            <ArrowUpDown className="w-3 h-3 text-[#94A3B8]" />
                          </div>
                        </th>
                        <th className="py-2.5 px-3">Event Action</th>
                        <th
                          onClick={() => handleSort('user')}
                          className="py-2.5 px-3 cursor-pointer hover:text-[#0F172A] transition"
                        >
                          <div className="flex items-center gap-1">
                            <span>User</span>
                            <ArrowUpDown className="w-3 h-3 text-[#94A3B8]" />
                          </div>
                        </th>
                        <th className="py-2.5 px-3">Host / Source IP</th>
                        <th className="py-2.5 px-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E2E8F0] bg-white">
                      {paginatedLogs.map((log) => {
                        const isExpanded = !!expandedRows[log.id];
                        const score = Number(log.yValue ?? log.severity_score ?? 1.0);
                        const isCopied = copiedId === log.id;

                        return (
                          <React.Fragment key={log.id}>
                            <tr
                              className={`hover:bg-[#F8FAFC] transition cursor-pointer ${
                                isExpanded ? 'bg-[#F8FAFC]' : ''
                              }`}
                              onClick={() => toggleRowExpansion(log.id)}
                            >
                              <td className="py-2.5 px-3 text-center text-[#94A3B8]">
                                {isExpanded ? (
                                  <ChevronDown className="w-4 h-4 text-[#0F172A]" />
                                ) : (
                                  <ChevronRight className="w-4 h-4 text-[#94A3B8]" />
                                )}
                              </td>

                              <td className="py-2.5 px-3 font-mono text-[11px] text-[#334155] whitespace-nowrap">
                                {log.timeLabel}
                              </td>

                              <td className="py-2.5 px-3 whitespace-nowrap">
                                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${sevBadgeClass(score)}`}>
                                  {score >= 7.0 && <Flame className="w-2.5 h-2.5 text-[#DC2626]" />}
                                  {score.toFixed(1)}
                                </span>
                              </td>

                              <td className="py-2.5 px-3 whitespace-nowrap">
                                <span
                                  className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold"
                                  style={{
                                    backgroundColor: `${catFill(log.category)}15`,
                                    color: catFill(log.category),
                                  }}
                                >
                                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: catFill(log.category) }} />
                                  {log.category}
                                </span>
                              </td>

                              <td className="py-2.5 px-3">
                                <div className="font-medium text-[#0F172A] leading-tight">
                                  {friendlyLabel(log.event_type)}
                                </div>
                                <div className="font-mono text-[10px] text-[#94A3B8]">
                                  {log.event_type}
                                </div>
                              </td>

                              <td className="py-2.5 px-3 font-mono text-[11px] text-[#475569]">
                                {log.user ? (
                                  <span className="px-1.5 py-0.5 rounded bg-[#F1F5F9] border border-[#E2E8F0] text-[#0F172A]">
                                    {log.user}
                                  </span>
                                ) : (
                                  <span className="text-[#94A3B8]">—</span>
                                )}
                              </td>

                              <td className="py-2.5 px-3 font-mono text-[11px] text-[#475569] whitespace-nowrap">
                                <div>{log.dest_host || log.host || '—'}</div>
                                {log.source_ip && (
                                  <div className="text-[10px] text-[#94A3B8]">{log.source_ip}</div>
                                )}
                              </td>

                              <td className="py-2.5 px-3 text-right whitespace-nowrap" onClick={e => e.stopPropagation()}>
                                <button
                                  onClick={() => handleSelect(log)}
                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-[#ECFDF5] hover:bg-[#D1FAE5] text-[#059669] border border-[#A7F3D0] transition shadow-subtle"
                                  title="Inspect in Forensic Evidence Inspector"
                                >
                                  <Eye className="w-3 h-3 text-[#10B981]" />
                                  <span>Inspect</span>
                                </button>
                              </td>
                            </tr>

                            {/* Expanded Row Detail Drawer */}
                            {isExpanded && (
                              <tr className="bg-[#F8FAFC]">
                                <td colSpan={8} className="p-4 border-b border-[#E2E8F0]">
                                  <div className="bg-white border border-[#E2E8F0] rounded-xl p-4 shadow-subtle space-y-3">
                                    <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2">
                                      <div className="flex items-center gap-2">
                                        <Database className="w-4 h-4 text-[#10B981]" />
                                        <span className="font-semibold text-xs text-[#0F172A]">
                                          Log Event Record: <span className="font-mono text-[#059669]">{log.id}</span>
                                        </span>
                                      </div>

                                      <div className="flex items-center gap-2">
                                        <button
                                          onClick={() => copyEventJson(log)}
                                          className="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium bg-white hover:bg-[#F8FAFC] text-[#475569] border border-[#CBD5E1] transition"
                                        >
                                          {isCopied ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3 text-[#64748B]" />}
                                          <span>{isCopied ? 'Copied' : 'Copy JSON'}</span>
                                        </button>

                                        <button
                                          onClick={() => handleSelect(log)}
                                          className="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-subtle transition"
                                        >
                                          <ExternalLink className="w-3 h-3" />
                                          <span>Evidence Inspector</span>
                                        </button>
                                      </div>
                                    </div>

                                    {/* Event Details Grid */}
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                                      <div className="p-2 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                                        <span className="text-[10px] text-[#64748B] block font-mono">Timestamp</span>
                                        <span className="font-mono font-semibold text-[#0F172A]">{log.timestamp}</span>
                                      </div>
                                      <div className="p-2 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                                        <span className="text-[10px] text-[#64748B] block font-mono">Event Type</span>
                                        <span className="font-semibold text-[#0F172A]">{friendlyLabel(log.event_type)}</span>
                                      </div>
                                      <div className="p-2 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                                        <span className="text-[10px] text-[#64748B] block font-mono">User / Identity</span>
                                        <span className="font-mono text-[#0F172A]">{log.user || 'None recorded'}</span>
                                      </div>
                                      <div className="p-2 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                                        <span className="text-[10px] text-[#64748B] block font-mono">Source IP / Host</span>
                                        <span className="font-mono text-[#0F172A]">{log.source_ip || log.host || 'Local'}</span>
                                      </div>
                                    </div>

                                    {/* Description / Explanation */}
                                    {(log.description || log.explanation || log.what_happened) && (
                                      <div className="p-2.5 rounded-lg bg-[#FFFBEB] border border-[#FEF3C7] text-xs text-[#92400E]">
                                        <span className="font-bold block mb-0.5">Analyst Note / Explanation:</span>
                                        <span>{log.description || log.explanation || log.what_happened}</span>
                                      </div>
                                    )}

                                    {/* Raw JSON Code Block */}
                                    <div>
                                      <span className="text-[10px] font-mono text-[#64748B] uppercase tracking-wider block mb-1 font-semibold">
                                        Raw Telemetry Payload
                                      </span>
                                      <pre className="p-2.5 rounded-lg bg-[#0F172A] text-[#E2E8F0] font-mono text-[11px] overflow-x-auto max-h-48 leading-relaxed">
                                        {JSON.stringify(log, null, 2)}
                                      </pre>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Table Pagination Controls */}
                <div className="flex items-center justify-between pt-2">
                  <span className="text-xs text-[#64748B]">
                    Page {currentPage} of {totalPages}
                  </span>

                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className="px-2.5 py-1 rounded text-xs font-medium bg-white hover:bg-[#F8FAFC] text-[#0F172A] border border-[#CBD5E1] transition disabled:opacity-40"
                    >
                      <ChevronLeft className="w-3.5 h-3.5 inline mr-1" />
                      Previous
                    </button>

                    <div className="flex items-center gap-1">
                      {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                        const pageNum = i + 1;
                        return (
                          <button
                            key={pageNum}
                            onClick={() => setCurrentPage(pageNum)}
                            className={`w-7 h-7 rounded text-xs font-semibold transition ${
                              currentPage === pageNum
                                ? 'bg-[#10B981] text-white shadow-subtle'
                                : 'bg-white hover:bg-[#F8FAFC] text-[#475569] border border-[#E2E8F0]'
                            }`}
                          >
                            {pageNum}
                          </button>
                        );
                      })}
                    </div>

                    <button
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      className="px-2.5 py-1 rounded text-xs font-medium bg-white hover:bg-[#F8FAFC] text-[#0F172A] border border-[#CBD5E1] transition disabled:opacity-40"
                    >
                      Next
                      <ChevronRight className="w-3.5 h-3.5 inline ml-1" />
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
