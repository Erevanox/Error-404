import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer, ComposedChart, Line, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ReferenceLine, Area
} from 'recharts';
import {
  X, Activity, ShieldAlert, Clock, User, Globe,
  ArrowLeft, ExternalLink, Eye, Info, FileDown,
  Network, Server, AlertTriangle, ChevronDown, ChevronUp
} from 'lucide-react';
import { apiClient } from '../api/client';

function formatTimestampDisplay(ts) {
  if (!ts) return 'Unknown';
  return ts.replace('T', ' ').replace('Z', ' UTC');
}

function formatTimeOnly(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toISOString().substring(11, 19);
}

function getSeverityColor(score) {
  if (score >= 7.0) return '#DC2626';
  if (score >= 4.5) return '#D97706';
  return '#2563EB';
}

function getSeverityLabel(score) {
  if (score >= 7.0) return 'High Risk';
  if (score >= 4.5) return 'Attention';
  return 'Informational';
}

/**
 * Incident Graph Modal — shown when analyst clicks "Graph" on a correlated incident.
 * Displays contextual severity progression & event volume for the SPECIFIC selected incident.
 */
export default function IncidentGraphModal({
  alert,
  events = [],
  onClose,
  onInspectEvent,
  onDownloadPdf
}) {
  const [selectedPointId, setSelectedPointId] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  if (!alert) return null;

  // Extract and sort real correlated events for the active incident
  const incidentEvents = useMemo(() => {
    let evs = alert.supporting_events || [];
    
    // Fallback to filtering global events by supporting_event_ids
    if ((!evs || evs.length === 0) && alert.supporting_event_ids && events) {
      const idSet = new Set(alert.supporting_event_ids);
      evs = events.filter(e => idSet.has(e.id));
    }

    // Sort chronologically
    return [...evs].sort((a, b) => {
      const tA = new Date(a.timestamp || 0).getTime();
      const tB = new Date(b.timestamp || 0).getTime();
      return tA - tB;
    });
  }, [alert, events]);

  // Build chart data
  const { chartData, hasSharedTimestamps } = useMemo(() => {
    if (!incidentEvents.length) return { chartData: [], hasSharedTimestamps: false };

    const groups = new Map();
    let sharedFound = false;

    incidentEvents.forEach((ev, idx) => {
      const timeKey = ev.timestamp || `unknown-${idx}`;
      if (!groups.has(timeKey)) {
        groups.set(timeKey, []);
      } else {
        sharedFound = true;
      }
      groups.get(timeKey).push(ev);
    });

    const data = [];
    let cumulativeVolume = 0;

    groups.forEach((evGroup, timeKey) => {
      const pointId = `point-${timeKey}`;
      const firstEv = evGroup[0];
      const count = evGroup.length;
      cumulativeVolume += count;

      const validScores = evGroup
        .map(e => e.severity_score)
        .filter(s => s !== null && s !== undefined && !isNaN(Number(s)))
        .map(Number);

      const maxScore = validScores.length > 0 ? Math.max(...validScores) : 1.0;
      const avgScore = validScores.length > 0 ? validScores.reduce((a, b) => a + b, 0) / validScores.length : 1.0;

      data.push({
        id: pointId,
        rawTimestamp: timeKey,
        timeDisplay: formatTimeOnly(timeKey),
        fullTimeDisplay: formatTimestampDisplay(timeKey),
        severity: Number(maxScore.toFixed(1)),
        avgSeverity: Number(avgScore.toFixed(1)),
        eventCount: count,
        cumulativeVolume,
        events: evGroup,
        primaryEvent: firstEv,
        category: firstEv.category || 'SECURITY',
        action: firstEv.action || firstEv.status || 'observed',
        user: firstEv.user || alert.primary_user || '-',
        host: firstEv.host || alert.primary_host || '-'
      });
    });

    return { chartData: data, hasSharedTimestamps: sharedFound };
  }, [incidentEvents, alert]);

  // Selected point
  const activePoint = useMemo(() => {
    if (!chartData.length) return null;
    if (selectedPointId) {
      const found = chartData.find(d => d.id === selectedPointId);
      if (found) return found;
    }
    return chartData.reduce((prev, curr) => (curr.severity > prev.severity ? curr : prev), chartData[0]);
  }, [chartData, selectedPointId]);

  const activeEvent = activePoint?.events?.[0] || null;

  // Relationship analysis
  const relationships = useMemo(() => {
    const users = new Set();
    const sourceIPs = new Set();
    const destIPs = new Set();
    const hosts = new Set();
    const destHosts = new Set();
    const categories = {};
    
    incidentEvents.forEach(ev => {
      if (ev.user) users.add(ev.user);
      if (ev.source_ip) sourceIPs.add(ev.source_ip);
      if (ev.dest_ip) destIPs.add(ev.dest_ip);
      if (ev.host) hosts.add(ev.host);
      if (ev.dest_host) destHosts.add(ev.dest_host);
      const cat = ev.category || 'UNKNOWN';
      categories[cat] = (categories[cat] || 0) + 1;
    });

    return { users: [...users], sourceIPs: [...sourceIPs], destIPs: [...destIPs], hosts: [...hosts], destHosts: [...destHosts], categories };
  }, [incidentEvents]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white border border-[#E2E8F0] rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden shadow-2xl flex flex-col text-[#0F172A]">
        
        {/* Header */}
        <div className="p-4 border-b border-[#E2E8F0] flex items-center justify-between bg-[#F8FAFC] shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 rounded-lg bg-[#EAF3FB] border border-[#BFDBFE] text-[#1677C8]">
              <Activity className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 className="text-sm font-bold text-[#0F172A] truncate">
                Incident Graph — {alert.id}
              </h2>
              <p className="text-[11px] text-[#64748B] truncate">{alert.title}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {onDownloadPdf && (
              <button
                onClick={() => onDownloadPdf(alert.id)}
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-[#F1F5F9] text-[#16A34A] border border-[#E2E8F0] transition flex items-center gap-1.5"
                title="Export PDF"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">PDF</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0F172A] bg-white hover:bg-[#F1F5F9] border border-[#E2E8F0] transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          
          {/* Incident Summary Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs">
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Incident ID</span>
              <span className="font-mono font-bold text-[#1677C8] text-[11px]">{alert.id}</span>
            </div>
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Risk</span>
              <span className="font-bold text-[#DC2626] text-[11px]">{alert.risk_score || 0}/100 ({(alert.severity || 'Medium').toUpperCase()})</span>
            </div>
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Account</span>
              <span className="font-mono font-bold text-[#252B33] text-[11px]">{alert.primary_user || '—'}</span>
            </div>
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Source IP</span>
              <span className="font-mono text-[#475569] text-[11px]">{alert.primary_ip || '—'}</span>
            </div>
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Events</span>
              <span className="font-bold text-[#059669] text-[11px]">{incidentEvents.length}</span>
            </div>
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-2">
              <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Time Window</span>
              <span className="font-mono text-[10px] text-[#475569] truncate block">
                {formatTimeOnly(alert.first_seen)} → {formatTimeOnly(alert.last_seen)}
              </span>
            </div>
          </div>

          {/* Chart */}
          {incidentEvents.length === 0 ? (
            <div className="py-12 text-center text-[#657180] flex flex-col items-center justify-center gap-2">
              <ShieldAlert className="w-8 h-8 text-[#CBD5E1]" />
              <p className="text-sm font-semibold text-[#252B33]">No correlated events for this incident.</p>
              <p className="text-xs text-[#657180] max-w-md">
                This alert does not have linked telemetry records. Try loading event data first.
              </p>
            </div>
          ) : incidentEvents.length === 1 ? (
            <div className="py-6 px-4 bg-[#F8FAFC] border border-[#DDE3EA] rounded-xl text-center space-y-2">
              <Info className="w-5 h-5 text-[#1677C8] mx-auto" />
              <p className="text-sm font-bold text-[#252B33]">Single Event Recorded</p>
              <p className="text-xs text-[#657180] max-w-lg mx-auto">
                This incident contains 1 event at <strong className="font-mono">{formatTimestampDisplay(incidentEvents[0].timestamp)}</strong> with severity <strong className="text-[#DC2626] font-mono">{incidentEvents[0].severity_score ?? 1.0}/10</strong>. A minimum of 2 events is needed for a trend line.
              </p>
            </div>
          ) : (
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl p-3">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-[#252B33] flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-[#1677C8]" />
                  Severity Progression & Event Volume
                </h3>
                {hasSharedTimestamps && (
                  <span className="text-[10px] text-[#D97706] bg-[#FEF3C7] border border-[#FDE68A] rounded px-2 py-0.5">
                    Grouped timestamps
                  </span>
                )}
              </div>
              <div className="w-full h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart
                    data={chartData}
                    margin={{ top: 5, right: 25, left: 0, bottom: 15 }}
                    onClick={(e) => {
                      if (e?.activePayload?.[0]?.payload?.id) {
                        setSelectedPointId(e.activePayload[0].payload.id);
                      }
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                    <XAxis
                      dataKey="timeDisplay"
                      tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                      tickLine={{ stroke: '#CBD5E1' }}
                      axisLine={{ stroke: '#CBD5E1' }}
                      label={{ value: 'Timeline (UTC)', position: 'insideBottom', offset: -10, fill: '#64748B', fontSize: 10 }}
                    />
                    <YAxis
                      yAxisId="severity"
                      domain={[0, 10]}
                      ticks={[0, 2, 4, 6, 8, 10]}
                      tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                      tickLine={{ stroke: '#CBD5E1' }}
                      axisLine={{ stroke: '#CBD5E1' }}
                      label={{ value: 'Severity', angle: -90, position: 'insideLeft', fill: '#64748B', fontSize: 10, offset: 10 }}
                    />
                    <YAxis
                      yAxisId="volume"
                      orientation="right"
                      domain={[0, (dataMax) => Math.max(5, dataMax + 1)]}
                      tick={{ fill: '#94A3B8', fontSize: 9, fontFamily: 'monospace' }}
                      tickLine={false}
                      axisLine={false}
                    />
                    <ReferenceLine yAxisId="severity" y={7.0} stroke="#EF4444" strokeDasharray="4 4" strokeWidth={1.5}
                      label={{ value: 'High Risk (7.0)', fill: '#EF4444', fontSize: 9, position: 'insideTopRight' }} />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload?.[0]?.payload) {
                          const d = payload[0].payload;
                          return (
                            <div className="bg-white border border-[#CBD5E1] p-2.5 rounded-lg shadow-lg text-xs space-y-1 max-w-xs">
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-mono font-bold text-[#0F172A]">{d.fullTimeDisplay}</span>
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase font-mono ${
                                  d.severity >= 7.0 ? 'bg-[#FDE8E8] text-[#C53030]' : 'bg-[#EAF3FB] text-[#1677C8]'
                                }`}>
                                  {d.severity}/10
                                </span>
                              </div>
                              <div className="text-[#475569]">
                                <div><strong>Action:</strong> {d.action}</div>
                                <div><strong>User:</strong> <span className="font-mono text-[#1677C8]">{d.user}</span></div>
                                {d.eventCount > 1 && <div className="text-[#D97706] font-semibold">{d.eventCount} events at this time</div>}
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Legend verticalAlign="top" align="right" wrapperStyle={{ paddingBottom: 5, fontSize: 10 }} />
                    <Bar yAxisId="volume" dataKey="eventCount" name="Events" fill="#E2E8F0" radius={[3, 3, 0, 0]} barSize={14} />
                    <Line
                      yAxisId="severity" type="monotone" dataKey="severity" name="Severity"
                      stroke="#1677C8" strokeWidth={2}
                      activeDot={{ r: 6, stroke: '#1677C8', strokeWidth: 2, fill: '#FFFFFF' }}
                      dot={(props) => {
                        const { cx, cy, payload } = props;
                        const isSelected = payload.id === activePoint?.id;
                        const isHigh = payload.severity >= 7.0;
                        return (
                          <circle key={payload.id} cx={cx} cy={cy}
                            r={isSelected ? 5 : 3.5}
                            fill={isSelected ? '#1677C8' : (isHigh ? '#DC2626' : '#FFFFFF')}
                            stroke={isHigh ? '#DC2626' : '#1677C8'} strokeWidth={2}
                            className="cursor-pointer" />
                        );
                      }}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Selected Event Detail */}
          {activeEvent && (
            <div className="bg-white border border-[#E2E8F0] rounded-xl p-3 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${
                    (activeEvent.severity_score || 1) >= 7.0
                      ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]'
                      : 'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]'
                  }`}>
                    {(activeEvent.status || 'OK').toUpperCase()}
                  </span>
                  <span className="text-xs font-bold text-[#252B33]">
                    Selected: <span className="font-mono text-[#1677C8]">{activeEvent.id}</span>
                  </span>
                </div>
                {onInspectEvent && (
                  <button
                    onClick={() => onInspectEvent(activeEvent)}
                    className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white transition flex items-center gap-1"
                  >
                    <Eye className="w-3 h-3" />
                    Evidence Inspector
                  </button>
                )}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
                <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                  <span className="text-[9px] text-[#657180] block font-sans">Timestamp</span>
                  <strong className="text-[#252B33] text-[10px]">{formatTimestampDisplay(activeEvent.timestamp)}</strong>
                </div>
                <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                  <span className="text-[9px] text-[#657180] block font-sans">Type</span>
                  <strong className="text-[#1677C8] text-[10px]">{activeEvent.event_type || 'event'}</strong>
                </div>
                <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                  <span className="text-[9px] text-[#657180] block font-sans">User</span>
                  <strong className="text-[#252B33] text-[10px]">{activeEvent.user || 'system'}</strong>
                </div>
                <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                  <span className="text-[9px] text-[#657180] block font-sans">Severity</span>
                  <strong className={`text-[10px] ${(activeEvent.severity_score || 1) >= 7.0 ? 'text-[#DC2626]' : 'text-[#1677C8]'}`}>
                    {activeEvent.severity_score ? activeEvent.severity_score.toFixed(1) : '1.0'}/10
                  </strong>
                </div>
              </div>
            </div>
          )}

          {/* Relationships Summary */}
          {incidentEvents.length > 0 && (
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl p-3">
              <button
                onClick={() => setShowDetails(v => !v)}
                className="flex items-center gap-2 text-xs text-[#657180] hover:text-[#252B33] font-medium transition w-full"
              >
                {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                <span>{showDetails ? 'Hide' : 'Show'} Entity Relationships & Details</span>
              </button>
              
              {showDetails && (
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="space-y-1">
                    <span className="text-[10px] text-[#657180] uppercase font-semibold block">Accounts</span>
                    {relationships.users.map(u => (
                      <span key={u} className="inline-block mr-1.5 px-2 py-0.5 bg-white border border-[#E2E8F0] rounded font-mono text-[#252B33]">{u}</span>
                    ))}
                    {relationships.users.length === 0 && <span className="text-[#94A3B8] italic">No user data</span>}
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-[#657180] uppercase font-semibold block">Source IPs</span>
                    {relationships.sourceIPs.map(ip => (
                      <span key={ip} className="inline-block mr-1.5 px-2 py-0.5 bg-white border border-[#E2E8F0] rounded font-mono text-[#252B33]">{ip}</span>
                    ))}
                    {relationships.sourceIPs.length === 0 && <span className="text-[#94A3B8] italic">Not recorded</span>}
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-[#657180] uppercase font-semibold block">Source Hosts</span>
                    {relationships.hosts.map(h => (
                      <span key={h} className="inline-block mr-1.5 px-2 py-0.5 bg-white border border-[#E2E8F0] rounded font-mono text-[#252B33]">{h}</span>
                    ))}
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-[#657180] uppercase font-semibold block">Destination Hosts/IPs</span>
                    {[...relationships.destHosts, ...relationships.destIPs].map(d => (
                      <span key={d} className="inline-block mr-1.5 px-2 py-0.5 bg-white border border-[#E2E8F0] rounded font-mono text-[#252B33]">{d}</span>
                    ))}
                    {relationships.destHosts.length === 0 && relationships.destIPs.length === 0 && <span className="text-[#94A3B8] italic">Not recorded</span>}
                  </div>
                  <div className="space-y-1 sm:col-span-2">
                    <span className="text-[10px] text-[#657180] uppercase font-semibold block">Event Categories</span>
                    {Object.entries(relationships.categories).map(([cat, count]) => (
                      <span key={cat} className="inline-block mr-1.5 px-2 py-0.5 bg-white border border-[#E2E8F0] rounded text-[#252B33]">
                        {cat}: <strong>{count}</strong>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-[#E2E8F0] bg-[#F8FAFC] flex justify-between items-center shrink-0">
          <span className="text-[10px] text-[#64748B] font-mono">
            {incidentEvents.length} events • {alert.id}
          </span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold text-[#64748B] hover:text-[#0F172A] bg-white hover:bg-[#F1F5F9] border border-[#E2E8F0] transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
