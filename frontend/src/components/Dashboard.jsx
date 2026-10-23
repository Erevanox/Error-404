import React, { useMemo, useState } from 'react';
import { 
  ShieldAlert, AlertTriangle, CheckCircle2, 
  Terminal, Shield, Upload, Zap, ArrowRight,
  Clock, Network, FileSearch, AlertCircle, PieChart as PieChartIcon
} from 'lucide-react';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, 
  Tooltip, Cell, CartesianGrid, PieChart, Pie, Sector 
} from 'recharts';

const renderActiveShape = (props) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
  return (
    <g>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius - 3}
        outerRadius={outerRadius + 8}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        style={{
          filter: `drop-shadow(0px 6px 14px ${fill}80)`,
          transition: 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
          cursor: 'pointer'
        }}
      />
      <Sector
        cx={cx}
        cy={cy}
        startAngle={startAngle}
        endAngle={endAngle}
        innerRadius={outerRadius + 11}
        outerRadius={outerRadius + 14}
        fill={fill}
        opacity={0.85}
      />
    </g>
  );
};

export default function Dashboard({ 
  stats, 
  events = [], 
  alerts = [], 
  onSelectAlert, 
  onInspectEvent,
  onNavigateTab, 
  onOpenUpload,
  onLoadScenario 
}) {
  const hasData = (events && events.length > 0) || (stats && stats.total_events > 0);
  const [activeSeverityIndex, setActiveSeverityIndex] = useState(null);
  const [hoveredSeverityIndex, setHoveredSeverityIndex] = useState(null);

  // 1. Bar Chart 1: Category Breakdown Bar Chart
  const categoryData = useMemo(() => {
    return [
      { 
        name: 'Authentication', 
        count: hasData ? (stats?.category_counts?.AUTHENTICATION || 0) : 0, 
        color: '#10B981' 
      },
      { 
        name: 'System', 
        count: hasData ? (stats?.category_counts?.SYSTEM || 0) : 0, 
        color: '#F59E0B' 
      },
      { 
        name: 'Network', 
        count: hasData ? (stats?.category_counts?.NETWORK || 0) : 0, 
        color: '#6366F1' 
      },
    ];
  }, [stats, hasData]);

  // 2. Bar Chart 2: Correlated Severity Breakdown Bar Chart
  const severityData = useMemo(() => {
    const counts = stats?.severity_distribution || {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };
    return [
      { name: 'Critical', count: hasData ? (counts.Critical || 0) : 0, color: '#EF4444' },
      { name: 'High', count: hasData ? (counts.High || 0) : 0, color: '#F59E0B' },
      { name: 'Medium', count: hasData ? (counts.Medium || 0) : 0, color: '#EAB308' },
      { name: 'Low', count: hasData ? (counts.Low || 0) : 0, color: '#10B981' },
    ];
  }, [stats, hasData]);

  const totalSeverityCount = useMemo(() => {
    return severityData.reduce((acc, curr) => acc + (curr.count || 0), 0);
  }, [severityData]);

  const activeIndexToDisplay = hoveredSeverityIndex !== null ? hoveredSeverityIndex : activeSeverityIndex;
  const activeSeverityItem = activeIndexToDisplay !== null ? severityData[activeIndexToDisplay] : null;
  const activePercentage = (activeSeverityItem && totalSeverityCount > 0)
    ? Math.round((activeSeverityItem.count / totalSeverityCount) * 100)
    : 0;

  // 3. Filter real suspicious events for Recent Activity table
  const suspiciousEvents = useMemo(() => {
    if (!events || events.length === 0) return [];
    return events
      .filter(e => (e.severity_score && e.severity_score >= 4.0) || e.status === 'failure' || e.action?.includes('fail'))
      .slice(0, 6);
  }, [events]);

  const totalRecords = hasData ? (stats?.total_records ?? stats?.total_events ?? events.length) : 0;
  const detectionAlerts = hasData ? (stats?.detection_alerts ?? suspiciousEvents.length) : 0;
  const correlatedAlerts = hasData ? (stats?.correlated_alerts ?? stats?.total_alerts ?? alerts.length) : 0;
  const validationErrors = hasData ? (stats?.validation_errors ?? 0) : 0;

  return (
    <div className="space-y-5 text-[#0F172A]">
      {/* ------------------------------------------------------------------ */}
      {/* STATS OVERVIEW ROW (Derived strictly from real data)               */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Total Records */}
        <div 
          onClick={() => hasData && onNavigateTab('scatter')}
          className={`bg-white border border-[#E2E8F0] rounded-xl p-4 transition-all shadow-card ${
            hasData ? 'cursor-pointer hover:border-[#10B981]/60 hover:bg-[#F8FAFC]' : 'opacity-90'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs text-[#64748B] font-medium">Total Records</span>
            <div className="p-2 rounded-lg bg-[#ECFDF5] text-[#059669]">
              <Terminal className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#0F172A]">
              {totalRecords}
            </span>
            <span className="text-[11px] text-[#64748B] font-mono">
              {hasData ? 'Ingested' : 'Logs'}
            </span>
          </div>
          <p className="text-[11px] text-[#94A3B8] mt-1">Normalized telemetry events</p>
        </div>

        {/* Detection Alerts */}
        <div 
          onClick={() => hasData && onNavigateTab('scatter')}
          className={`bg-white border border-[#E2E8F0] rounded-xl p-4 transition-all shadow-card ${
            hasData ? 'cursor-pointer hover:border-[#EF4444]/60 hover:bg-[#F8FAFC]' : 'opacity-90'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs text-[#64748B] font-medium">Detection Alerts</span>
            <div className="p-2 rounded-lg bg-[#FEF2F2] text-[#DC2626]">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#DC2626]">
              {detectionAlerts}
            </span>
            <span className="text-[11px] text-[#64748B] font-mono">
              {hasData ? 'Suspicious' : 'Triggers'}
            </span>
          </div>
          <p className="text-[11px] text-[#94A3B8] mt-1">Anomalous flagged events</p>
        </div>

        {/* Correlated Alerts */}
        <div 
          onClick={() => hasData && onNavigateTab('alerts')}
          className={`bg-white border border-[#E2E8F0] rounded-xl p-4 transition-all shadow-card ${
            hasData ? 'cursor-pointer hover:border-[#F59E0B]/60 hover:bg-[#F8FAFC]' : 'opacity-90'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs text-[#64748B] font-medium">Correlated Alerts</span>
            <div className="p-2 rounded-lg bg-[#FFFBEB] text-[#D97706]">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#D97706]">
              {correlatedAlerts}
            </span>
            <span className="text-[11px] text-[#64748B] font-mono">
              {hasData ? 'Incidents' : 'Clusters'}
            </span>
          </div>
          <p className="text-[11px] text-[#94A3B8] mt-1">Multi-event attack sequences</p>
        </div>

        {/* Validation Errors */}
        <div 
          className="bg-white border border-[#E2E8F0] rounded-xl p-4 transition-all shadow-card opacity-90"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs text-[#64748B] font-medium">Validation Errors</span>
            <div className="p-2 rounded-lg bg-[#F1F5F9] text-[#64748B]">
              <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#0F172A]">
              {validationErrors}
            </span>
            <span className="text-[11px] text-[#059669] font-mono font-medium">Clean</span>
          </div>
          <p className="text-[11px] text-[#94A3B8] mt-1">Parser integrity check</p>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* CONDITIONAL: EMPTY DASHBOARD vs ACTIVE INVESTIGATION               */}
      {/* ------------------------------------------------------------------ */}
      {!hasData ? (
        /* Empty Dashboard Experience */
        <div className="rounded-xl bg-white border border-[#E2E8F0] p-8 md:p-12 text-center shadow-card space-y-6 max-w-3xl mx-auto my-6">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-[#ECFDF5] border border-[#A7F3D0] flex items-center justify-center text-[#059669]">
            <Upload className="w-7 h-7" />
          </div>

          <div className="space-y-2 max-w-lg mx-auto">
            <h2 className="text-xl md:text-2xl font-bold text-[#0F172A] tracking-tight">
              Start an Investigation
            </h2>
            <p className="text-sm text-[#64748B] leading-relaxed">
              Upload a CSV log file to analyze events, identify suspicious activity, and trace related evidence.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <button
              onClick={onOpenUpload}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-sm transition"
            >
              <Upload className="w-4 h-4" />
              <span>Upload Log File</span>
            </button>
            <button
              onClick={() => onLoadScenario('canonical')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-[#F8FAFC] hover:bg-[#F1F5F9] text-[#0F172A] border border-[#CBD5E1] transition shadow-subtle"
            >
              <Zap className="w-4 h-4 text-[#F59E0B]" />
              <span>Load Demo Data</span>
            </button>
          </div>

          <div className="pt-6 border-t border-[#E2E8F0] grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
            <div className="p-3.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[11px] font-mono font-semibold text-[#059669] block mb-1">01. INGEST</span>
              <p className="text-xs text-[#64748B]">Multi-source CSV and JSON authentication, process, and network records.</p>
            </div>
            <div className="p-3.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[11px] font-mono font-semibold text-[#D97706] block mb-1">02. CORRELATE</span>
              <p className="text-xs text-[#64748B]">Automated detection of brute force, credential reuse, and lateral pivots.</p>
            </div>
            <div className="p-3.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[11px] font-mono font-semibold text-[#6366F1] block mb-1">03. TRACE</span>
              <p className="text-xs text-[#64748B]">Entity traceback graph with verifiable timeline evidence and forensic dossier.</p>
            </div>
          </div>
        </div>
      ) : (
        /* Active Investigation: Two Bar Charts & Suspicious Events */
        <>
          {/* TWO DISTINCT BAR CHARTS ROW */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Bar Chart 1: Event Category Telemetry */}
            <div className="bg-white border border-[#E2E8F0] rounded-xl p-4 shadow-card">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold text-[#0F172A]">Event Category Telemetry</h3>
                  <p className="text-[11px] text-[#64748B]">Normalized ingestion volume by telemetry domain</p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#F1F5F9] text-[#64748B] font-semibold border border-[#E2E8F0]">
                  Category Bar Chart
                </span>
              </div>

              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryData} margin={{ top: 12, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
                    <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} />
                    <YAxis stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#E2E8F0', borderRadius: '8px', fontSize: '11px', color: '#0F172A', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                      formatter={(val, name) => [`${val} events`, name]}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={48}>
                      {categoryData.map((entry, index) => (
                        <Cell key={`cat-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Legend Footer */}
              <div className="grid grid-cols-3 gap-2 mt-2 pt-2 border-t border-[#E2E8F0] text-center">
                {categoryData.map((c) => (
                  <div key={c.name} className="px-2 py-1 bg-[#F8FAFC] rounded-md border border-[#E2E8F0]">
                    <span className="text-[10px] text-[#64748B] block font-medium">{c.name}</span>
                    <span className="text-sm font-bold font-mono" style={{ color: c.color }}>{c.count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Circular Chart 2: Correlated Severity Breakdown (Donut Chart) */}
            <div className="bg-white border border-[#E2E8F0] rounded-xl p-4 shadow-card">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="text-sm font-semibold text-[#0F172A] flex items-center gap-1.5">
                    <PieChartIcon className="w-4 h-4 text-[#EF4444]" />
                    <span>Correlated Severity Breakdown</span>
                  </h3>
                  <p className="text-[11px] text-[#64748B]">Classification of detected alert risk ratings</p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#F1F5F9] text-[#64748B] font-semibold border border-[#E2E8F0]">
                  Severity Donut Chart
                </span>
              </div>

              <div className="relative h-48 w-full flex items-center justify-center">
                {totalSeverityCount > 0 ? (
                  <>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityData}
                          dataKey="count"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={70}
                          paddingAngle={totalSeverityCount > 0 ? 3 : 0}
                          activeIndex={activeIndexToDisplay !== null ? activeIndexToDisplay : undefined}
                          activeShape={renderActiveShape}
                          isAnimationActive={true}
                          animationDuration={700}
                          animationEasing="ease-out"
                          onMouseEnter={(_, index) => setHoveredSeverityIndex(index)}
                          onMouseLeave={() => setHoveredSeverityIndex(null)}
                          onClick={(_, index) => {
                            setActiveSeverityIndex(prev => prev === index ? null : index);
                          }}
                          cursor="pointer"
                        >
                          {severityData.map((entry, index) => (
                            <Cell 
                              key={`sev-pie-${index}`} 
                              fill={entry.count > 0 ? entry.color : '#E2E8F0'} 
                              opacity={activeIndexToDisplay === null || activeIndexToDisplay === index ? 1 : 0.35}
                              className="transition-opacity duration-200 outline-none"
                            />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>

                    {/* Integrated Center Metric (Eliminates Tooltip Collision) */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center select-none">
                      <span 
                        className="text-[10px] font-mono uppercase tracking-wider font-semibold transition-colors duration-200"
                        style={{ color: activeSeverityItem ? activeSeverityItem.color : '#64748B' }}
                      >
                        {activeSeverityItem ? activeSeverityItem.name : 'Total Alerts'}
                      </span>
                      <span 
                        className="text-2xl font-bold font-mono tracking-tight transition-all duration-200"
                        style={{ color: activeSeverityItem ? activeSeverityItem.color : '#0F172A' }}
                      >
                        {activeSeverityItem ? activeSeverityItem.count : totalSeverityCount}
                      </span>
                      <span className="text-[10px] text-[#94A3B8] font-mono transition-opacity duration-200">
                        {activeSeverityItem 
                          ? `${activePercentage}% of total` 
                          : 'Detected Risk'}
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center text-center space-y-1.5 text-[#94A3B8]">
                    <CheckCircle2 className="w-8 h-8 text-[#10B981]/50" />
                    <span className="text-xs font-medium text-[#64748B]">Zero Suspicious Alerts</span>
                    <span className="text-[11px] text-[#94A3B8]">No correlated threat signatures detected</span>
                  </div>
                )}
              </div>

              {/* Clickable Legend Footer with interactive highlight */}
              <div className="grid grid-cols-4 gap-2 mt-2 pt-2 border-t border-[#E2E8F0] text-center">
                {severityData.map((s, idx) => {
                  const isSelected = activeIndexToDisplay === idx;
                  return (
                    <button
                      key={s.name}
                      type="button"
                      onMouseEnter={() => setHoveredSeverityIndex(idx)}
                      onMouseLeave={() => setHoveredSeverityIndex(null)}
                      onClick={() => setActiveSeverityIndex(prev => prev === idx ? null : idx)}
                      className={`px-1.5 py-1 rounded-md border transition-all text-center ${
                        isSelected 
                          ? 'bg-white ring-2 shadow-sm scale-105' 
                          : 'bg-[#F8FAFC] hover:bg-white border-[#E2E8F0]'
                      }`}
                      style={{
                        borderColor: isSelected ? s.color : '#E2E8F0',
                        boxShadow: isSelected ? `0 2px 8px ${s.color}33` : 'none'
                      }}
                      title={`Click to inspect ${s.name} severity details`}
                    >
                      <span className="text-[10px] text-[#64748B] block font-medium flex items-center justify-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: s.color }} />
                        <span>{s.name}</span>
                      </span>
                      <span className="text-sm font-bold font-mono" style={{ color: s.color }}>{s.count}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Recent Suspicious Activity Table */}
          <div className="bg-white border border-[#E2E8F0] rounded-xl overflow-hidden shadow-card">
            <div className="p-3.5 border-b border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#EF4444]" />
                <h3 className="text-sm font-semibold text-[#0F172A]">Recent Suspicious Activity</h3>
              </div>
              <button
                onClick={() => onNavigateTab('scatter')}
                className="text-xs text-[#059669] hover:underline font-semibold flex items-center gap-1"
              >
                <span>View In Log Explorer</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-[#64748B] font-mono text-[11px]">
                    <th className="py-2.5 px-4 font-semibold">Timestamp</th>
                    <th className="py-2.5 px-4 font-semibold">Source / User</th>
                    <th className="py-2.5 px-4 font-semibold">Event Type</th>
                    <th className="py-2.5 px-4 font-semibold">Severity</th>
                    <th className="py-2.5 px-4 font-semibold">Status</th>
                    <th className="py-2.5 px-4 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0] text-[#0F172A]">
                  {suspiciousEvents.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-[#64748B] text-xs">
                        No suspicious events detected in current log stream.
                      </td>
                    </tr>
                  ) : (
                    suspiciousEvents.map((ev) => (
                      <tr 
                        key={ev.id}
                        className="hover:bg-[#F8FAFC] transition-colors cursor-pointer"
                        onClick={() => onInspectEvent && onInspectEvent(ev)}
                      >
                        <td className="py-2.5 px-4 font-mono text-[#0F172A] whitespace-nowrap">
                          {ev.timestamp ? ev.timestamp.substring(11, 19) : '-'}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className="font-semibold text-[#0F172A]">{ev.user || 'system'}</span>
                          <span className="text-[#64748B] text-[11px] block">{ev.host || ev.source_ip || '-'}</span>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-[11px] text-[#64748B]">
                          {ev.event_type}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            ev.severity_score >= 7.0 
                              ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]'
                              : 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]'
                          }`}>
                            Score {ev.severity_score}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-[11px] capitalize">
                          <span className={ev.status === 'failure' ? 'text-[#DC2626] font-semibold' : 'text-[#64748B]'}>
                            {ev.status || ev.action || 'detected'}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onInspectEvent && onInspectEvent(ev);
                            }}
                            className="px-2.5 py-1 rounded bg-white hover:bg-[#F1F5F9] text-[#059669] text-[11px] font-semibold border border-[#CBD5E1] transition shadow-subtle"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
