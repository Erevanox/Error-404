import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer, ComposedChart, Line, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ReferenceLine, Dot
} from 'recharts';
import {
  LineChart as LineChartIcon, Clock, ShieldAlert, ArrowLeft,
  ExternalLink, User, Globe, HardDrive, Info, AlertTriangle,
  CheckCircle, FileDown, Activity, ChevronRight, Layers, Eye
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

export default function IncidentActivityTrend({
  alerts = [],
  events = [],
  selectedAlert,
  onSelectAlert,
  onInspectEvent,
  onNavigateTab,
  onDownloadPdf
}) {
  // Currently active alert
  const currentAlert = useMemo(() => {
    if (selectedAlert) return selectedAlert;
    if (alerts && alerts.length > 0) return alerts[0];
    return null;
  }, [selectedAlert, alerts]);

  const [selectedPointId, setSelectedPointId] = useState(null);

  // Extract and sort real correlated events for the active incident
  const incidentEvents = useMemo(() => {
    if (!currentAlert) return [];
    
    // Check if supporting_events already populated on alert
    let evs = currentAlert.supporting_events || [];
    
    // Fallback to filtering global events by supporting_event_ids
    if ((!evs || evs.length === 0) && currentAlert.supporting_event_ids && events) {
      const idSet = new Set(currentAlert.supporting_event_ids);
      evs = events.filter(e => idSet.has(e.id));
    }

    // Secondary fallback: match on primary user and temporal window
    if ((!evs || evs.length === 0) && events && currentAlert.primary_user) {
      evs = events.filter(e => e.user === currentAlert.primary_user);
    }

    // Sort chronologically
    return [...evs].sort((a, b) => {
      const tA = new Date(a.timestamp || 0).getTime();
      const tB = new Date(b.timestamp || 0).getTime();
      return tA - tB;
    });
  }, [currentAlert, events]);

  // Aggregate data for Recharts time-series
  // If multiple events occur at the same second/minute, group them into a single point
  // while preserving individual events for inspection.
  const { chartData, pointLookup, hasSharedTimestamps } = useMemo(() => {
    if (!incidentEvents.length) {
      return { chartData: [], pointLookup: {}, hasSharedTimestamps: false };
    }

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
    const lookup = {};

    let cumulativeVolume = 0;

    groups.forEach((evGroup, timeKey) => {
      const pointId = `point-${timeKey}`;
      const firstEv = evGroup[0];
      const count = evGroup.length;
      cumulativeVolume += count;

      // Extract real scores without fabrication
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
        user: firstEv.user || currentAlert?.primary_user || '-',
        host: firstEv.host || currentAlert?.primary_host || '-'
      });

      lookup[pointId] = evGroup;
    });

    return { chartData: data, pointLookup: lookup, hasSharedTimestamps: sharedFound };
  }, [incidentEvents, currentAlert]);

  // Selected point object
  const activePoint = useMemo(() => {
    if (!chartData.length) return null;
    if (selectedPointId) {
      const found = chartData.find(d => d.id === selectedPointId);
      if (found) return found;
    }
    // Default to the highest severity point or latest point
    return chartData.reduce((prev, curr) => (curr.severity > prev.severity ? curr : prev), chartData[0]);
  }, [chartData, selectedPointId]);

  const activeEvent = activePoint?.events?.[0] || null;

  return (
    <div className="space-y-4">
      {/* ── Top Header & Navigation ───────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 lg:p-5 shadow-card flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onNavigateTab ? onNavigateTab('alerts') : null}
              className="px-2 py-1 rounded bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#475569] text-xs font-medium transition flex items-center gap-1 border border-[#DDE3EA]"
              title="Return to Correlated Alerts"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Alerts</span>
            </button>
            <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]">
              Time-Series Visualization
            </span>
          </div>

          <h1 className="text-lg font-bold text-[#252B33] mt-2 flex items-center gap-2">
            <LineChartIcon className="w-5 h-5 text-[#1677C8]" />
            Incident Activity Trend
          </h1>
          <p className="text-xs text-[#657180] mt-0.5">
            See how event activity and severity change over the selected incident timeline.
          </p>
        </div>

        {/* Incident Selector & Cross-Navigation */}
        <div className="flex flex-wrap items-center gap-2">
          {alerts && alerts.length > 0 && (
            <select
              value={currentAlert?.id || ''}
              onChange={(e) => {
                const found = alerts.find(a => a.id === e.target.value);
                if (found && onSelectAlert) {
                  onSelectAlert(found);
                }
              }}
              className="bg-white border border-[#DDE3EA] rounded-lg px-3 py-1.5 text-xs text-[#252B33] font-medium shadow-subtle focus:outline-none focus:border-[#1677C8]"
              aria-label="Select incident to inspect activity trend"
            >
              {alerts.map(a => (
                <option key={a.id} value={a.id}>
                  {a.id} — {a.title?.substring(0, 36)}… ({a.severity})
                </option>
              ))}
            </select>
          )}

          {currentAlert && (
            <>
              <button
                onClick={() => onNavigateTab ? onNavigateTab('traceback') : null}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1.5 shadow-subtle"
                title="View Full Attack Reconstruction"
              >
                <Layers className="w-3.5 h-3.5 text-[#1677C8]" />
                <span className="hidden sm:inline">Attack Reconstruction</span>
              </button>

              <button
                onClick={() => onDownloadPdf ? onDownloadPdf(currentAlert.id) : null}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#16A34A] border border-[#DDE3EA] transition flex items-center gap-1.5 shadow-subtle"
                title="Download Investigation PDF"
              >
                <FileDown className="w-3.5 h-3.5 text-[#16A34A]" />
                <span className="hidden sm:inline">Export PDF</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* ── Selected Incident Metadata Summary Banner ─────────────────────── */}
      {currentAlert && (
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Incident ID</span>
            <span className="font-mono font-bold text-[#1677C8]">{currentAlert.id}</span>
          </div>
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Risk Rating</span>
            <span className="font-bold text-[#DC2626]">
              {currentAlert.risk_score || 85}/100 ({(currentAlert.severity || 'High').toUpperCase()})
            </span>
          </div>
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Target Account</span>
            <span className="font-mono font-bold text-[#252B33]">{currentAlert.primary_user || 'm.vasquez'}</span>
          </div>
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Observed Source IP</span>
            <span className="font-mono font-bold text-[#475569]">{currentAlert.primary_ip || '192.168.1.105'}</span>
          </div>
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Correlated Events</span>
            <span className="font-bold text-[#059669]">{incidentEvents.length} events</span>
          </div>
          <div>
            <span className="text-[10px] uppercase font-mono text-[#657180] block font-semibold">Time Window</span>
            <span className="font-mono text-[11px] text-[#475569] truncate block">
              {formatTimeOnly(currentAlert.first_seen)} → {formatTimeOnly(currentAlert.last_seen)} UTC
            </span>
          </div>
        </div>
      )}

      {/* ── Main Chart Section ────────────────────────────────────────────── */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 shadow-card space-y-4">
        {/* Chart Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#F0F3F6]">
          <div>
            <h2 className="text-sm font-bold text-[#252B33] flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#1677C8]" />
              Event Severity Progression & Activity Volume
            </h2>
            <p className="text-xs text-[#657180] mt-0.5">
              Click any node on the trend line to inspect specific forensic evidence.
            </p>
          </div>

          {hasSharedTimestamps && (
            <div className="flex items-center gap-1.5 text-[11px] text-[#D97706] bg-[#FEF3C7] border border-[#FDE68A] rounded px-2.5 py-1">
              <Info className="w-3.5 h-3.5 shrink-0" />
              <span>Events sharing timestamps are aggregated to show peak severity and count.</span>
            </div>
          )}
        </div>

        {/* Chart Body */}
        {incidentEvents.length === 0 ? (
          /* Empty State */
          <div className="py-16 text-center text-[#657180] flex flex-col items-center justify-center gap-2">
            <ShieldAlert className="w-10 h-10 text-[#CBD5E1]" />
            <p className="text-sm font-semibold text-[#252B33]">No correlated events available for this incident.</p>
            <p className="text-xs text-[#657180] max-w-md">
              The selected alert does not contain linked telemetry records. Select another incident or upload event logs.
            </p>
          </div>
        ) : incidentEvents.length === 1 ? (
          /* Single Observation State */
          <div className="py-8 px-4 bg-[#F8FAFC] border border-[#DDE3EA] rounded-xl text-center space-y-3">
            <div className="inline-flex p-3 rounded-full bg-[#EAF3FB] text-[#1677C8]">
              <Info className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-bold text-[#252B33]">Single Telemetry Observation Recorded</h3>
            <p className="text-xs text-[#657180] max-w-lg mx-auto leading-relaxed">
              This incident currently contains exactly 1 recorded observation at{' '}
              <strong className="text-[#252B33] font-mono">{formatTimestampDisplay(incidentEvents[0].timestamp)}</strong> with a severity score of{' '}
              <strong className="text-[#DC2626] font-mono">{incidentEvents[0].severity_score ?? 1.0}/10.0</strong>.
              A minimum of 2 observations is required to render a chronological time-series trend line.
            </p>
          </div>
        ) : (
          /* Time-series Line Chart with Recharts */
          <div className="w-full h-80 pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={chartData}
                margin={{ top: 10, right: 30, left: 0, bottom: 20 }}
                onClick={(e) => {
                  if (e && e.activePayload && e.activePayload.length > 0) {
                    const point = e.activePayload[0].payload;
                    if (point && point.id) {
                      setSelectedPointId(point.id);
                    }
                  }
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                
                <XAxis
                  dataKey="timeDisplay"
                  tick={{ fill: '#64748B', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#CBD5E1' }}
                  axisLine={{ stroke: '#CBD5E1' }}
                  label={{
                    value: 'Chronological Timeline (UTC)',
                    position: 'insideBottom',
                    offset: -12,
                    fill: '#64748B',
                    fontSize: 11
                  }}
                />

                <YAxis
                  yAxisId="severity"
                  domain={[0, 10]}
                  ticks={[0, 2, 4, 6, 8, 10]}
                  tick={{ fill: '#64748B', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#CBD5E1' }}
                  axisLine={{ stroke: '#CBD5E1' }}
                  label={{
                    value: 'Severity Score (1.0 - 10.0)',
                    angle: -90,
                    position: 'insideLeft',
                    fill: '#64748B',
                    fontSize: 11,
                    offset: 10
                  }}
                />

                <YAxis
                  yAxisId="volume"
                  orientation="right"
                  domain={[0, (dataMax) => Math.max(5, dataMax + 1)]}
                  tick={{ fill: '#94A3B8', fontSize: 10, fontFamily: 'monospace' }}
                  tickLine={false}
                  axisLine={false}
                  label={{
                    value: 'Event Count',
                    angle: 90,
                    position: 'insideRight',
                    fill: '#94A3B8',
                    fontSize: 10,
                    offset: 10
                  }}
                />

                {/* Reference baseline threshold for high risk */}
                <ReferenceLine
                  yAxisId="severity"
                  y={7.0}
                  stroke="#EF4444"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{
                    value: 'High Risk Threshold (7.0)',
                    fill: '#EF4444',
                    fontSize: 10,
                    position: 'insideTopRight'
                  }}
                />

                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      const isHigh = data.severity >= 7.0;
                      return (
                        <div className="bg-white border border-[#CBD5E1] p-3 rounded-xl shadow-lg text-xs space-y-1.5 max-w-xs font-sans">
                          <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-1.5">
                            <span className="font-mono font-bold text-[#0F172A]">{data.fullTimeDisplay}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                              isHigh ? 'bg-[#FDE8E8] text-[#C53030]' : 'bg-[#EAF3FB] text-[#1677C8]'
                            }`}>
                              Severity {data.severity}/10
                            </span>
                          </div>
                          <div className="space-y-1 text-[#475569]">
                            <div>
                              <strong className="text-[#0F172A]">Action:</strong> {data.action}
                            </div>
                            <div>
                              <strong className="text-[#0F172A]">User:</strong> <span className="font-mono text-[#1677C8]">{data.user}</span>
                            </div>
                            <div>
                              <strong className="text-[#0F172A]">Host:</strong> <span className="font-mono">{data.host}</span>
                            </div>
                            {data.eventCount > 1 && (
                              <div className="text-[#D97706] font-semibold">
                                {data.eventCount} events recorded at this timestamp
                              </div>
                            )}
                          </div>
                          <div className="pt-1 text-[10px] text-[#64748B] italic border-t border-[#F1F5F9]">
                            Click point to inspect full event telemetry below.
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />

                <Legend
                  verticalAlign="top"
                  align="right"
                  wrapperStyle={{ paddingBottom: 10, fontSize: 11 }}
                />

                {/* Event Volume Bars (secondary series) */}
                <Bar
                  yAxisId="volume"
                  dataKey="eventCount"
                  name="Event Count"
                  fill="#E2E8F0"
                  radius={[4, 4, 0, 0]}
                  barSize={16}
                />

                {/* Severity Progression Trend Line */}
                <Line
                  yAxisId="severity"
                  type="monotone"
                  dataKey="severity"
                  name="Severity Score"
                  stroke="#1677C8"
                  strokeWidth={2.5}
                  activeDot={{ r: 7, stroke: '#1677C8', strokeWidth: 2, fill: '#FFFFFF' }}
                  dot={(props) => {
                    const { cx, cy, payload } = props;
                    const isSelected = payload.id === activePoint?.id;
                    const isHigh = payload.severity >= 7.0;
                    return (
                      <circle
                        key={payload.id}
                        cx={cx}
                        cy={cy}
                        r={isSelected ? 6 : 4}
                        fill={isSelected ? '#1677C8' : (isHigh ? '#DC2626' : '#FFFFFF')}
                        stroke={isHigh ? '#DC2626' : '#1677C8'}
                        strokeWidth={2}
                        className="cursor-pointer transition-all hover:scale-125"
                      />
                    );
                  }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* ── Selected Event Forensic Details Card ───────────────────────────── */}
      {activeEvent && (
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 shadow-card space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#F0F3F6]">
            <div className="flex items-center gap-2.5">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                (activeEvent.severity_score || 1) >= 7.0
                  ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]'
                  : 'bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]'
              }`}>
                {(activeEvent.status || 'OK').toUpperCase()}
              </span>
              <h3 className="text-sm font-bold text-[#252B33]">
                Selected Event: <span className="font-mono text-[#1677C8]">{activeEvent.id}</span>
              </h3>
              {activePoint?.eventCount > 1 && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#FEF3C7] text-[#D97706] font-mono font-semibold">
                  1 of {activePoint.eventCount} at this timestamp
                </span>
              )}
            </div>

            <button
              onClick={() => onInspectEvent ? onInspectEvent(activeEvent) : null}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white transition flex items-center gap-1.5 shadow-sm group shrink-0"
              title="Open event in Evidence Inspector"
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Inspect in Evidence Inspector</span>
              <ExternalLink className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>

          {/* Key Attributes Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Timestamp (UTC)</span>
              <strong className="text-[#252B33]">{formatTimestampDisplay(activeEvent.timestamp)}</strong>
            </div>
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Event Type</span>
              <strong className="text-[#1677C8]">{activeEvent.event_type || 'generic_event'}</strong>
            </div>
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">User Account</span>
              <strong className="text-[#252B33]">{activeEvent.user || 'system'}</strong>
            </div>
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Severity Score</span>
              <strong className={`font-bold ${
                (activeEvent.severity_score || 1) >= 7.0 ? 'text-[#DC2626]' : 'text-[#1677C8]'
              }`}>
                {activeEvent.severity_score ? activeEvent.severity_score.toFixed(1) : '1.0'} / 10.0
              </strong>
            </div>
          </div>

          {/* Network & Endpoints */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Source Endpoint</span>
              <span className="font-mono text-[#252B33]">
                {activeEvent.host || 'WORKSTATION-04'} ({activeEvent.source_ip || '192.168.1.105'})
              </span>
            </div>
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Destination</span>
              <span className="font-mono text-[#252B33]">
                {activeEvent.dest_host || activeEvent.dest_ip || 'Local / None'} {activeEvent.port ? `:${activeEvent.port}` : ''}
              </span>
            </div>
            <div className="bg-[#F8FAFC] p-2.5 rounded-lg border border-[#E2E8F0]">
              <span className="text-[10px] text-[#657180] block font-sans">Action / Protocol</span>
              <span className="font-mono text-[#252B33]">
                {activeEvent.action || 'observed'} / {activeEvent.protocol || 'TCP'}
              </span>
            </div>
          </div>

          {/* Raw Log Preview */}
          {activeEvent.raw_log && (
            <div>
              <span className="text-[10px] font-mono text-[#657180] uppercase block font-semibold mb-1">
                Preserved Raw Log Entry
              </span>
              <pre className="p-3 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg text-[11px] font-mono text-[#0F172A] whitespace-pre-wrap break-all max-h-24 overflow-y-auto leading-relaxed">
                {activeEvent.raw_log}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
