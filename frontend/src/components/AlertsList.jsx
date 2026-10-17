import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, AlertTriangle, Clock, User, 
  Network, FileDown, FolderPlus, ArrowRight, ArrowLeft,
  Search, Filter, ChevronRight, Activity, CheckCircle, 
  HelpCircle, AlertCircle, Info, ExternalLink, Hash,
  Database, Terminal, Shield, Lock, Eye, Check, ChevronDown, ChevronUp,
  LineChart
} from 'lucide-react';
import { apiClient } from '../api/client';

// ─── Helpers for Truthful Explainability ─────────────────────────────────────

function formatTimestamp(ts) {
  if (!ts) return 'Not recorded';
  return ts.replace('T', ' ').replace('Z', ' UTC');
}

function calculateTimeDeltaSeconds(tsA, tsB) {
  if (!tsA || !tsB) return null;
  const tA = new Date(tsA).getTime();
  const tB = new Date(tsB).getTime();
  if (isNaN(tA) || isNaN(tB)) return null;
  return Math.round(Math.abs(tB - tA) / 1000);
}

function sortEventsChronologically(events) {
  if (!events || !events.length) return { sorted: [], unverified: [] };
  const sorted = [];
  const unverified = [];
  
  events.forEach(ev => {
    const t = ev.timestamp ? new Date(ev.timestamp).getTime() : NaN;
    if (isNaN(t)) {
      unverified.push(ev);
    } else {
      sorted.push({ ...ev, _time: t });
    }
  });

  sorted.sort((a, b) => a._time - b._time);
  return { sorted, unverified };
}

function getPriorityBadgeClass(severity) {
  const sev = (severity || '').toUpperCase();
  if (sev === 'CRITICAL') {
    return 'bg-[#FDE8E8] text-[#C53030] border-[#F8B4B4]';
  }
  if (sev === 'HIGH') {
    return 'bg-[#FEEBC8] text-[#DD6B20] border-[#FBD38D]';
  }
  if (sev === 'MEDIUM') {
    return 'bg-[#FEFCBF] text-[#B7791F] border-[#FAF089]';
  }
  return 'bg-[#EAF3FB] text-[#1677C8] border-[#BFDBFE]';
}

function getEventResultBadge(action, status) {
  const act = (action || status || '').toLowerCase();
  if (act.includes('fail') || act.includes('deny') || act.includes('block') || act.includes('error')) {
    return {
      label: action || status || 'failed',
      className: 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]'
    };
  }
  if (act.includes('success') || act.includes('allow') || act.includes('accept')) {
    return {
      label: action || status || 'success',
      className: 'bg-emerald-50 text-[#16A34A] border border-emerald-200'
    };
  }
  return {
    label: action || status || 'observed',
    className: 'bg-[#F0F3F6] text-[#475569] border border-[#DDE3EA]'
  };
}

/**
 * Section A: What happened?
 * 1-2 simple sentences using actual log fields.
 */
function buildWhatHappened(ev) {
  if (!ev) return 'No event selected.';
  const act = (ev.action || ev.status || '').toLowerCase();
  const type = (ev.event_type || ev.category || 'security event').replace(/_/g, ' ');
  const user = ev.user ? `'${ev.user}'` : 'an unspecified user account';
  const ip = ev.source_ip ? `from source IP ${ev.source_ip}` : 'without a recorded source IP';
  const host = ev.host ? `on host ${ev.host}` : '';
  const time = ev.timestamp ? `at ${formatTimestamp(ev.timestamp)}` : '';

  let verb = `An event of type "${type}"`;
  if (act.includes('fail')) {
    verb = `A failed ${type} attempt was recorded`;
  } else if (act.includes('success')) {
    verb = `A successful ${type} event was recorded`;
  } else if (act.includes('block')) {
    verb = `A blocked ${type} attempt was logged`;
  }

  return `${verb} for account ${user} ${ip} ${host} ${time}.`.replace(/\s+/g, ' ').trim();
}

/**
 * Section B: Why is it important?
 * Explains investigative significance based on event type, severity score, detection rule.
 */
function buildWhyImportant(ev, alert) {
  if (!ev) return '';
  const reasons = [];
  const type = (ev.event_type || '').toLowerCase();
  const action = (ev.action || '').toLowerCase();
  const score = ev.severity_score ?? 0;

  if (action.includes('fail') || type.includes('failed') || type.includes('brute_force')) {
    reasons.push('Repeated failed login attempts may indicate someone is trying different credentials or conducting an automated authentication probe.');
  } else if (action.includes('success') || type.includes('success')) {
    reasons.push('A successful login event following failed attempts represents an essential investigation milestone, requiring immediate verification of subsequent activity.');
  } else if (type.includes('lateral') || type.includes('smb') || type.includes('rdp')) {
    reasons.push('Network access between internal workstations is characteristic of lateral movement across network boundaries.');
  } else if (type.includes('exfil') || (ev.bytes_out && ev.bytes_out > 50000)) {
    reasons.push('Unusually high outbound data transfer requires evaluation to ensure sensitive information was not extracted.');
  }

  if (score >= 7.0) {
    reasons.push(`A high risk score of ${score.toFixed(1)}/10.0 prioritizes this event for immediate analyst review.`);
  } else if (score >= 4.5) {
    reasons.push(`A risk score of ${score.toFixed(1)}/10.0 reflects activity deviating from standard baseline telemetry.`);
  }

  if (alert?.rule_id) {
    reasons.push(`This event was evaluated under correlation rule "${alert.rule_id}".`);
  }

  reasons.push('This event alone does not prove malicious activity; correlation with surrounding records is necessary.');

  return reasons.join(' ');
}

/**
 * Section E: What remains unknown?
 * Identifies important missing information truthful to the dataset.
 */
function buildUnknowns(ev, allEvents, alert) {
  const unknowns = [];
  if (!ev) return unknowns;

  if (ev.source_ip) {
    unknowns.push(`The available logs do not establish who operated or controlled source IP ${ev.source_ip}.`);
  } else {
    unknowns.push('The source IP address for this event was not recorded in the telemetry.');
  }

  const hasSuccess = allEvents?.some(e => {
    const act = (e.action || e.status || e.event_type || '').toLowerCase();
    return act.includes('success');
  });
  if (!hasSuccess) {
    unknowns.push('No successful login event was found in the available records for this incident.');
  }

  const hasResourceAccess = allEvents?.some(e => {
    const t = (e.event_type || '').toLowerCase();
    const c = (e.category || '').toLowerCase();
    return c === 'network' || t.includes('access') || t.includes('transfer') || t.includes('file');
  });
  if (!hasResourceAccess) {
    unknowns.push('No subsequent resource-access or data exfiltration event was found in the available records.');
  }

  unknowns.push('The available evidence does not establish whether the account was compromised or credentials were mistyped.');
  unknowns.push('Endpoint operating system process trees and packet-level inspection were not available in this log stream.');

  return unknowns;
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AlertsList({ 
  alerts, 
  events,
  investigatingAlert: controlledInvestigatingAlert,
  onInvestigateAlert,
  onSelectAlert, 
  onInspectEvidence,
  onNavigateTraceback, 
  onNavigateGraph,
  onCreateCase,
  onDownloadPdf 
}) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [search, setSearch] = useState('');
  const [expandedCards, setExpandedCards] = useState(new Set());

  // Active investigation state
  const [activeAlertId, setActiveAlertId] = useState(controlledInvestigatingAlert?.id || null);
  const [activeAlertDetail, setActiveAlertDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState(null);

  // Sync with controlled investigatingAlert prop
  useEffect(() => {
    if (controlledInvestigatingAlert?.id && controlledInvestigatingAlert.id !== activeAlertId) {
      loadIncident(controlledInvestigatingAlert);
    }
  }, [controlledInvestigatingAlert]);

  // Load incident details and events
  const loadIncident = async (alertItem) => {
    if (!alertItem) return;
    setActiveAlertId(alertItem.id);
    setLoadingDetail(true);

    try {
      const detail = await apiClient.getAlertById(alertItem.id);
      setActiveAlertDetail(detail);

      // Determine initial selected event
      const eventsList = detail.supporting_events || [];
      if (eventsList.length > 0) {
        const { sorted } = sortEventsChronologically(eventsList);
        setSelectedEventId(sorted[0]?.id || eventsList[0].id);
      }
    } catch (err) {
      console.warn('Falling back to local events matching for alert:', err);
      // Fallback: match supporting_event_ids from events prop
      const matchedEvents = (events || []).filter(e => 
        alertItem.supporting_event_ids?.includes(e.id)
      );
      const fallbackDetail = {
        ...alertItem,
        supporting_events: matchedEvents
      };
      setActiveAlertDetail(fallbackDetail);
      if (matchedEvents.length > 0) {
        const { sorted } = sortEventsChronologically(matchedEvents);
        setSelectedEventId(sorted[0]?.id || matchedEvents[0].id);
      }
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleStartInvestigation = (alertItem) => {
    loadIncident(alertItem);
    if (onInvestigateAlert) {
      onInvestigateAlert(alertItem);
    }
  };

  const handleExitInvestigation = () => {
    setActiveAlertId(null);
    setActiveAlertDetail(null);
    setSelectedEventId(null);
    if (onInvestigateAlert) {
      onInvestigateAlert(null);
    }
  };

  const toggleCardExpand = (alertId) => {
    setExpandedCards(prev => {
      const next = new Set(prev);
      if (next.has(alertId)) next.delete(alertId);
      else next.add(alertId);
      return next;
    });
  };

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    return alerts.filter(a => {
      if (filterSeverity !== 'ALL' && (a.severity || '').toUpperCase() !== filterSeverity.toUpperCase()) return false;
      if (search) {
        const q = search.toLowerCase();
        const match = 
          a.id.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          (a.primary_user && a.primary_user.toLowerCase().includes(q)) ||
          (a.primary_ip && a.primary_ip.toLowerCase().includes(q)) ||
          (a.what_happened && a.what_happened.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [alerts, filterSeverity, search]);

  // Derived investigation data
  const supportingEvents = activeAlertDetail?.supporting_events || [];
  const { sorted: chronologicalEvents, unverified: unverifiedEvents } = useMemo(() => {
    return sortEventsChronologically(supportingEvents);
  }, [supportingEvents]);

  const allDisplayEvents = useMemo(() => {
    return [...chronologicalEvents, ...unverifiedEvents];
  }, [chronologicalEvents, unverifiedEvents]);

  const selectedEvent = useMemo(() => {
    if (!selectedEventId && allDisplayEvents.length > 0) return allDisplayEvents[0];
    return allDisplayEvents.find(e => e.id === selectedEventId) || allDisplayEvents[0] || null;
  }, [selectedEventId, allDisplayEvents]);

  // Find index in chronological sequence for prev/next
  const selectedIndex = useMemo(() => {
    if (!selectedEvent) return -1;
    return chronologicalEvents.findIndex(e => e.id === selectedEvent.id);
  }, [selectedEvent, chronologicalEvents]);

  const prevEvent = selectedIndex > 0 ? chronologicalEvents[selectedIndex - 1] : null;
  const nextEvent = (selectedIndex >= 0 && selectedIndex < chronologicalEvents.length - 1) 
    ? chronologicalEvents[selectedIndex + 1] 
    : null;

  // Counts & flags for Investigation Summary & Evidence Verification
  const suspiciousEventCount = useMemo(() => {
    return supportingEvents.filter(e => {
      const score = e.severity_score ?? 0;
      const act = (e.action || e.status || '').toLowerCase();
      return score >= 4.5 || act.includes('fail') || act.includes('deny') || act.includes('block');
    }).length;
  }, [supportingEvents]);

  const hasSuccessfulLogin = useMemo(() => {
    return supportingEvents.some(e => {
      const act = (e.action || e.status || e.event_type || '').toLowerCase();
      return act.includes('success');
    });
  }, [supportingEvents]);

  const hasResourceAccess = useMemo(() => {
    return supportingEvents.some(e => {
      const cat = (e.category || '').toLowerCase();
      const typ = (e.event_type || '').toLowerCase();
      return cat === 'network' || typ.includes('access') || typ.includes('transfer') || typ.includes('file');
    });
  }, [supportingEvents]);

  // ═══════════════════════════════════════════════════════════════════════════
  // VIEW MODE: INTERACTIVE INCIDENT INVESTIGATION
  // ═══════════════════════════════════════════════════════════════════════════
  if (activeAlertId && activeAlertDetail) {
    const alert = activeAlertDetail;

    return (
      <div className="space-y-5 animate-fadeIn">
        {/* Top Navigation & Return Bar */}
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-card">
          <button
            onClick={handleExitInvestigation}
            className="flex items-center gap-2 text-xs font-semibold text-[#1677C8] hover:text-[#1366AC] transition group"
          >
            <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-1" />
            <span>← Back to All Correlated Alerts</span>
          </button>

          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs text-[#657180] font-mono">Incident ID:</span>
            <span className="font-mono text-xs font-bold text-[#252B33] bg-[#F0F3F6] px-2 py-0.5 rounded border border-[#DDE3EA]">
              {alert.id}
            </span>

            {/* Quick Actions */}
            <button
              onClick={() => onNavigateTraceback?.(alert)}
              className="ml-2 px-2.5 py-1 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle"
              title="View Relationship Traceback Graph"
            >
              <Network className="w-3.5 h-3.5 text-[#1677C8]" />
              <span className="hidden md:inline">Graph</span>
            </button>
            <button
              onClick={() => onCreateCase?.(alert)}
              className="px-2.5 py-1 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle"
              title="Create Investigation Case"
            >
              <FolderPlus className="w-3.5 h-3.5 text-[#1677C8]" />
              <span className="hidden md:inline">Case</span>
            </button>
            <button
              onClick={() => onDownloadPdf?.(alert.id)}
              className="px-2.5 py-1 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle"
              title="Download Incident Report"
            >
              <FileDown className="w-3.5 h-3.5 text-[#16A34A]" />
              <span className="hidden md:inline">PDF</span>
            </button>
          </div>
        </div>

        {/* ── 5. SIMPLE INVESTIGATION SUMMARY ───────────────────────────────── */}
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 shadow-card space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4 pb-4 border-b border-[#DDE3EA]">
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${getPriorityBadgeClass(alert.severity)}`}>
                  {(alert.severity || 'Medium').toUpperCase()} PRIORITY
                </span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-[#FEFCBF] text-[#B7791F] border border-[#FAF089]">
                  Possible incident
                </span>
                <span className="text-xs text-[#657180] font-mono">
                  Rule: {alert.rule_id || 'Correlated Multi-Event'}
                </span>
              </div>
              <h1 className="text-lg font-bold text-[#252B33]">
                {alert.title}
              </h1>
              <p className="text-xs text-[#475569] mt-1 leading-relaxed max-w-4xl">
                {alert.what_happened}
              </p>
            </div>

            {/* Risk Score Pill */}
            <div className="flex items-center gap-3 shrink-0 bg-[#F8FAFC] border border-[#DDE3EA] rounded-xl p-3">
              <div className="text-right">
                <span className="text-[10px] uppercase font-semibold text-[#657180] block">Risk Score</span>
                <span className="text-xl font-mono font-bold text-[#252B33]">
                  {alert.risk_score ?? 'N/A'}<span className="text-xs text-[#94A3B8] font-normal"> / 100</span>
                </span>
              </div>
              <Activity className="w-7 h-7 text-[#1677C8]" />
            </div>
          </div>

          {/* Investigation Summary Attributes Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-1">
            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-2.5">
              <span className="text-[10px] font-semibold uppercase text-[#657180] block">Affected Account</span>
              <span className="text-xs font-mono font-bold text-[#1677C8] truncate block mt-0.5" title={alert.primary_user || 'Not specified'}>
                {alert.primary_user || 'Not specified'}
              </span>
            </div>

            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-2.5">
              <span className="text-[10px] font-semibold uppercase text-[#657180] block">Source IP</span>
              <span className="text-xs font-mono font-bold text-[#252B33] truncate block mt-0.5" title={alert.primary_ip || 'Not recorded'}>
                {alert.primary_ip || 'Not recorded'}
              </span>
            </div>

            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-2.5">
              <span className="text-[10px] font-semibold uppercase text-[#657180] block">Related Events</span>
              <span className="text-xs font-mono font-bold text-[#252B33] block mt-0.5">
                {supportingEvents.length} events
              </span>
            </div>

            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-2.5">
              <span className="text-[10px] font-semibold uppercase text-[#657180] block">Suspicious Events</span>
              <span className="text-xs font-mono font-bold text-[#DD6B20] block mt-0.5">
                {suspiciousEventCount} flagged
              </span>
            </div>

            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-2.5 col-span-2 sm:col-span-1 lg:col-span-2">
              <span className="text-[10px] font-semibold uppercase text-[#657180] block">Observed Time Window</span>
              <span className="text-xs font-mono text-[#475569] block mt-0.5 truncate" title={`${formatTimestamp(alert.first_seen)} - ${formatTimestamp(alert.last_seen)}`}>
                {formatTimestamp(alert.first_seen).substring(11, 19)} → {formatTimestamp(alert.last_seen).substring(11, 19)}
              </span>
            </div>
          </div>

          {/* Explicit Evidence Quality Distinctions */}
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#F0F3F6] text-[11px]">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE] font-medium">
              <Check className="w-3 h-3 text-[#1677C8]" />
              <strong>OBSERVED:</strong> {supportingEvents.length} records verified in log telemetry
            </span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-50 text-[#B7791F] border border-[#FBD38D] font-medium">
              <Activity className="w-3 h-3 text-[#B7791F]" />
              <strong>INFERRED:</strong> Multi-event correlation rule hypothesis
            </span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#F8FAFC] text-[#657180] border border-[#DDE3EA] font-medium">
              <HelpCircle className="w-3 h-3 text-[#94A3B8]" />
              <strong>UNKNOWN:</strong> External operator identity & end intent not captured
            </span>
          </div>
        </div>

        {/* ── 2 & 3. FLOWCHART & INTERACTIVE NODE DETAILS ───────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">

          {/* LEFT: Chronological Flowchart (7 cols) */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 shadow-card">
              <div className="flex items-center justify-between pb-3 border-b border-[#DDE3EA]">
                <div>
                  <h2 className="text-sm font-bold text-[#252B33] flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#1677C8]" />
                    <span>Chronological Incident Flowchart</span>
                  </h2>
                  <p className="text-[11px] text-[#657180] mt-0.5">
                    Arranged in chronological order from raw records. Click any node to inspect evidence.
                  </p>
                </div>
                <span className="text-[11px] font-mono font-medium text-[#657180] bg-[#F0F3F6] px-2 py-0.5 rounded">
                  {allDisplayEvents.length} Sequence Nodes
                </span>
              </div>

              {/* Flowchart Sequence */}
              <div className="pt-4 space-y-3">
                {allDisplayEvents.length === 0 ? (
                  <div className="p-8 text-center text-xs text-[#657180] bg-[#F8FAFC] rounded-lg border border-dashed border-[#DDE3EA]">
                    No event records currently associated with this correlation group.
                  </div>
                ) : (
                  chronologicalEvents.map((ev, idx) => {
                    const isSelected = selectedEvent?.id === ev.id;
                    const resBadge = getEventResultBadge(ev.action, ev.status);
                    const isSuspicious = (ev.severity_score ?? 0) >= 4.5 || (ev.action || '').toLowerCase().includes('fail');
                    const nextEv = chronologicalEvents[idx + 1];
                    const timeDelta = nextEv ? calculateTimeDeltaSeconds(ev.timestamp, nextEv.timestamp) : null;
                    const sameUser = nextEv && ev.user && nextEv.user && ev.user === nextEv.user;
                    const sameIp = nextEv && ev.source_ip && nextEv.source_ip && ev.source_ip === nextEv.source_ip;

                    return (
                      <React.Fragment key={ev.id}>
                        {/* Flowchart Node Card */}
                        <div
                          onClick={() => setSelectedEventId(ev.id)}
                          className={`relative rounded-xl p-4 transition-all cursor-pointer border ${
                            isSelected 
                              ? 'bg-blue-50/40 border-[#1677C8] shadow-md ring-2 ring-[#1677C8]/20' 
                              : 'bg-white border-[#DDE3EA] hover:border-[#1677C8]/60 hover:shadow-sm'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-3">
                            {/* Sequence number & Title */}
                            <div className="flex items-start gap-3">
                              <span className={`w-7 h-7 rounded-lg flex items-center justify-center font-mono text-xs font-bold shrink-0 ${
                                isSelected
                                  ? 'bg-[#1677C8] text-white shadow-sm'
                                  : isSuspicious
                                  ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]'
                                  : 'bg-[#F0F3F6] text-[#475569] border border-[#DDE3EA]'
                              }`}>
                                {idx + 1}
                              </span>

                              <div className="space-y-1">
                                <div className="flex flex-wrap items-center gap-2">
                                  <h3 className={`text-xs font-bold ${isSelected ? 'text-[#1677C8]' : 'text-[#252B33]'}`}>
                                    {(ev.event_type || ev.category || 'Security Event').replace(/_/g, ' ').toUpperCase()}
                                  </h3>
                                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold uppercase ${resBadge.className}`}>
                                    {resBadge.label}
                                  </span>
                                  {ev.severity_score != null && (
                                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${
                                      ev.severity_score >= 7.0 ? 'bg-[#FDE8E8] text-[#C53030]' :
                                      ev.severity_score >= 4.5 ? 'bg-[#FEEBC8] text-[#DD6B20]' :
                                      'bg-[#EAF3FB] text-[#1677C8]'
                                    }`}>
                                      {ev.severity_score.toFixed(1)} / 10
                                    </span>
                                  )}
                                </div>

                                {/* Node Metadata Details */}
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-[#657180] font-mono pt-1">
                                  <div className="flex items-center gap-1">
                                    <Clock className="w-3 h-3 text-[#94A3B8] shrink-0" />
                                    <span>{formatTimestamp(ev.timestamp)}</span>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <User className="w-3 h-3 text-[#94A3B8] shrink-0" />
                                    <span>User: <strong className="text-[#252B33]">{ev.user || 'Not recorded'}</strong></span>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <Network className="w-3 h-3 text-[#94A3B8] shrink-0" />
                                    <span>Source IP: <strong className="text-[#252B33]">{ev.source_ip || 'Not recorded'}</strong></span>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <Database className="w-3 h-3 text-[#94A3B8] shrink-0" />
                                    <span>Host: <strong className="text-[#252B33]">{ev.host || ev.dest_host || 'Not recorded'}</strong></span>
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Selection Radio / Indicator */}
                            <div className="shrink-0 pt-0.5">
                              <span className={`text-[11px] font-medium px-2 py-1 rounded transition ${
                                isSelected 
                                  ? 'bg-[#1677C8] text-white' 
                                  : 'text-[#657180] bg-[#F0F3F6] hover:bg-[#E2E8F0]'
                              }`}>
                                {isSelected ? 'Selected' : 'View'}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Chronological Connector Arrow */}
                        {nextEv && (
                          <div className="flex flex-col items-center py-0.5">
                            <div className="w-px h-2.5 bg-[#CBD5E1]" />
                            <div className="bg-[#F8FAFC] border border-[#DDE3EA] rounded-full px-3 py-1 flex items-center gap-1.5 text-[10px] text-[#657180] font-mono shadow-subtle">
                              <ArrowRight className="w-3 h-3 text-[#1677C8] rotate-90" />
                              <span>occurred next in available records</span>
                              {timeDelta != null && (
                                <span className="text-[#1677C8] font-bold">
                                  (+{timeDelta}s)
                                </span>
                              )}
                              {(sameUser || sameIp) && (
                                <span className="text-[#475569] border-l border-[#CBD5E1] pl-1.5 ml-1">
                                  {sameUser && sameIp ? 'Same User & IP' : sameUser ? 'Same User' : 'Same IP'}
                                </span>
                              )}
                            </div>
                            <div className="w-px h-2.5 bg-[#CBD5E1]" />
                          </div>
                        )}
                      </React.Fragment>
                    );
                  })
                )}

                {/* Graceful unverified / missing timestamp events section */}
                {unverifiedEvents.length > 0 && (
                  <div className="mt-6 pt-4 border-t border-[#DDE3EA]">
                    <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 mb-3">
                      <span className="font-bold block">Notice: Events with Missing or Unverified Timestamps</span>
                      The following {unverifiedEvents.length} event(s) have missing or invalid timestamp formats. 
                      Their exact chronological position cannot be proven from available records and is not guessed.
                    </div>
                    {unverifiedEvents.map((ev, i) => (
                      <div
                        key={ev.id}
                        onClick={() => setSelectedEventId(ev.id)}
                        className={`rounded-lg p-3 border mb-2 cursor-pointer transition ${
                          selectedEvent?.id === ev.id ? 'bg-blue-50 border-[#1677C8]' : 'bg-white border-[#DDE3EA]'
                        }`}
                      >
                        <span className="text-xs font-bold text-[#252B33]">
                          [Unsequenced] {ev.event_type || ev.category} (ID: {ev.id})
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── EXPLICIT MISSING EVIDENCE CALLOUTS (Prompt Requirement 2) ── */}
                <div className="mt-6 pt-4 border-t border-[#DDE3EA] space-y-2.5">
                  <span className="text-[10px] font-semibold uppercase text-[#657180] tracking-wider block">
                    Telemetry Boundary & Evidence Verification
                  </span>

                  {!hasSuccessfulLogin && (
                    <div className="p-3 rounded-lg border border-dashed border-[#CBD5E1] bg-[#F8FAFC] text-xs text-[#657180] flex items-start gap-2.5">
                      <HelpCircle className="w-4 h-4 text-[#94A3B8] shrink-0 mt-0.5" />
                      <div>
                        <span className="font-semibold text-[#252B33] block">
                          No successful login event was found in the available records
                        </span>
                        <p className="text-[11px] text-[#657180] mt-0.5 leading-relaxed">
                          All recorded authentication attempts for this user within this incident sequence failed. 
                          No event establishing successful credential access was found in the ingested telemetry.
                        </p>
                      </div>
                    </div>
                  )}

                  {!hasResourceAccess && (
                    <div className="p-3 rounded-lg border border-dashed border-[#CBD5E1] bg-[#F8FAFC] text-xs text-[#657180] flex items-start gap-2.5">
                      <HelpCircle className="w-4 h-4 text-[#94A3B8] shrink-0 mt-0.5" />
                      <div>
                        <span className="font-semibold text-[#252B33] block">
                          No subsequent resource-access event was found in the available logs
                        </span>
                        <p className="text-[11px] text-[#657180] mt-0.5 leading-relaxed">
                          No post-authentication file access, administrative privilege changes, or database query events 
                          were observed in the current log stream for this entity.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* RIGHT: Interactive Selected Node Details (5 cols) */}
          <div className="lg:col-span-5 space-y-4">
            {selectedEvent ? (
              <div className="bg-white border border-[#DDE3EA] rounded-xl p-5 shadow-card space-y-4 sticky top-4">
                {/* Node Details Header */}
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-[#DDE3EA]">
                  <div>
                    <span className="text-[10px] font-mono text-[#1677C8] font-bold uppercase tracking-wider block">
                      Sequence Node Details · {selectedIndex >= 0 ? `Step ${selectedIndex + 1} of ${chronologicalEvents.length}` : 'Unsequenced'}
                    </span>
                    <h3 className="text-base font-bold text-[#252B33] mt-0.5">
                      {(selectedEvent.event_type || selectedEvent.category || 'Event Record').replace(/_/g, ' ')}
                    </h3>
                    <span className="font-mono text-xs text-[#657180] block mt-0.5">
                      Event ID: {selectedEvent.id}
                    </span>
                  </div>

                  <span className={`text-[10px] font-mono px-2 py-1 rounded font-bold uppercase border ${
                    getEventResultBadge(selectedEvent.action, selectedEvent.status).className
                  }`}>
                    {selectedEvent.action || selectedEvent.status || 'Observed'}
                  </span>
                </div>

                {/* ── A. WHAT HAPPENED? ──────────────────────────────────────── */}
                <div className="space-y-1 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-3">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#1677C8] flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" />
                    <span>A. What happened?</span>
                  </span>
                  <p className="text-xs text-[#252B33] leading-relaxed">
                    {buildWhatHappened(selectedEvent)}
                  </p>
                </div>

                {/* ── B. WHY IS IT IMPORTANT? ────────────────────────────────── */}
                <div className="space-y-1 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg p-3">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#DD6B20] flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>B. Why is it important?</span>
                  </span>
                  <p className="text-xs text-[#475569] leading-relaxed">
                    {buildWhyImportant(selectedEvent, alert)}
                  </p>
                </div>

                {/* ── C. WHAT HAPPENED BEFORE AND AFTER? ─────────────────────── */}
                <div className="space-y-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#657180] block">
                    C. What happened before and after?
                  </span>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {/* Preceding event */}
                    {prevEvent ? (
                      <button
                        onClick={() => setSelectedEventId(prevEvent.id)}
                        className="text-left p-2.5 rounded-lg border border-[#DDE3EA] hover:border-[#1677C8] bg-white transition group"
                      >
                        <span className="text-[10px] text-[#1677C8] font-bold block flex items-center gap-1">
                          <ArrowLeft className="w-3 h-3 transition-transform group-hover:-translate-x-0.5" />
                          <span>Preceding Event (#{selectedIndex})</span>
                        </span>
                        <span className="text-xs font-semibold text-[#252B33] block truncate mt-0.5">
                          {prevEvent.event_type || prevEvent.category}
                        </span>
                        <span className="text-[10px] font-mono text-[#657180] block">
                          {prevEvent.timestamp ? prevEvent.timestamp.substring(11, 19) : '—'}
                        </span>
                      </button>
                    ) : (
                      <div className="p-2.5 rounded-lg border border-dashed border-[#DDE3EA] bg-[#F8FAFC] text-[11px] text-[#94A3B8] italic">
                        First event in this incident sequence.
                      </div>
                    )}

                    {/* Following event */}
                    {nextEvent ? (
                      <button
                        onClick={() => setSelectedEventId(nextEvent.id)}
                        className="text-left p-2.5 rounded-lg border border-[#DDE3EA] hover:border-[#1677C8] bg-white transition group"
                      >
                        <span className="text-[10px] text-[#1677C8] font-bold block flex items-center justify-between">
                          <span>Following Event (#{selectedIndex + 2})</span>
                          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" />
                        </span>
                        <span className="text-xs font-semibold text-[#252B33] block truncate mt-0.5">
                          {nextEvent.event_type || nextEvent.category}
                        </span>
                        <span className="text-[10px] font-mono text-[#657180] block">
                          {nextEvent.timestamp ? nextEvent.timestamp.substring(11, 19) : '—'}
                        </span>
                      </button>
                    ) : (
                      <div className="p-2.5 rounded-lg border border-dashed border-[#DDE3EA] bg-[#F8FAFC] text-[11px] text-[#94A3B8] italic">
                        Final event recorded in this sequence.
                      </div>
                    )}
                  </div>
                </div>

                {/* ── D. EVIDENCE (Structured Fields) ───────────────────────── */}
                <div className="space-y-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#657180] block">
                    D. Specific Log Evidence
                  </span>

                  <div className="border border-[#DDE3EA] rounded-lg overflow-hidden text-xs">
                    <div className="divide-y divide-[#F0F3F6]">
                      <div className="flex items-center justify-between p-2 bg-[#F8FAFC]">
                        <span className="text-[#657180] font-mono text-[11px]">Timestamp:</span>
                        <span className="font-mono text-[#252B33] font-medium">{formatTimestamp(selectedEvent.timestamp)}</span>
                      </div>
                      <div className="flex items-center justify-between p-2">
                        <span className="text-[#657180] font-mono text-[11px]">Username:</span>
                        <span className="font-mono text-[#1677C8] font-bold">{selectedEvent.user || 'Not recorded'}</span>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-[#F8FAFC]">
                        <span className="text-[#657180] font-mono text-[11px]">Source IP:</span>
                        <span className="font-mono text-[#252B33] font-semibold">{selectedEvent.source_ip || 'Not recorded'}</span>
                      </div>
                      <div className="flex items-center justify-between p-2">
                        <span className="text-[#657180] font-mono text-[11px]">Event Type:</span>
                        <span className="font-mono text-[#252B33]">{selectedEvent.event_type || 'N/A'}</span>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-[#F8FAFC]">
                        <span className="text-[#657180] font-mono text-[11px]">Result / Action:</span>
                        <span className={`font-mono font-bold px-1.5 py-0.5 rounded text-[11px] ${
                          (selectedEvent.action || '').toLowerCase().includes('fail')
                            ? 'bg-[#FDE8E8] text-[#C53030]'
                            : 'bg-emerald-50 text-[#16A34A]'
                        }`}>
                          {selectedEvent.action || selectedEvent.status || 'Observed'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-2">
                        <span className="text-[#657180] font-mono text-[11px]">Target Host:</span>
                        <span className="font-mono text-[#252B33]">{selectedEvent.host || selectedEvent.dest_host || 'Not recorded'}</span>
                      </div>
                      <div className="flex items-center justify-between p-2 bg-[#F8FAFC]">
                        <span className="text-[#657180] font-mono text-[11px]">Detection Rule:</span>
                        <span className="font-mono text-[#1677C8] text-[11px] truncate max-w-[200px]" title={alert.rule_id || 'Correlated Multi-Event'}>
                          {alert.rule_id || 'Correlated Multi-Event'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* ── E. WHAT REMAINS UNKNOWN? ───────────────────────────────── */}
                <div className="space-y-1.5 bg-[#FFFBEB] border border-[#FDE68A] rounded-lg p-3 text-xs">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#B45309] flex items-center gap-1.5">
                    <HelpCircle className="w-3.5 h-3.5 text-[#B45309]" />
                    <span>E. What remains unknown?</span>
                  </span>
                  <ul className="space-y-1 text-[#78350F] text-[11px] leading-relaxed list-disc list-inside">
                    {buildUnknowns(selectedEvent, supportingEvents, alert).map((unk, idx) => (
                      <li key={idx}>{unk}</li>
                    ))}
                  </ul>
                </div>

                {/* ── 4. CLEAR "INVESTIGATE EVIDENCE →" ACTION BUTTON ───────── */}
                <div className="pt-2 border-t border-[#DDE3EA]">
                  <button
                    onClick={() => onInspectEvidence?.(selectedEvent, alert)}
                    className="w-full py-2.5 px-4 rounded-lg bg-[#1677C8] hover:bg-[#1366AC] text-white font-semibold text-xs transition flex items-center justify-center gap-2 shadow-sm group"
                  >
                    <span>Investigate Evidence</span>
                    <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                  </button>
                  <span className="text-[10px] text-[#657180] text-center block mt-1.5">
                    Opens Evidence Inspector for event {selectedEvent.id} with verified raw telemetry.
                  </span>
                </div>
              </div>
            ) : (
              <div className="bg-white border border-[#DDE3EA] rounded-xl p-8 text-center text-xs text-[#657180] shadow-card">
                Select an event from the flowchart to view interactive explanation and evidence.
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VIEW MODE: CORRELATED ALERTS LIST (Compact Cards)
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="space-y-4">
      {/* Controls Header */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-card">
        <div>
          <h2 className="text-base font-bold text-[#252B33] flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#C53030]" />
            <span>Correlated Security Incidents</span>
          </h2>
          <p className="text-xs text-[#657180] mt-0.5">
            Multi-event correlated alerts with chronological incident flowcharts and evidence tracing.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-white border border-[#DDE3EA] rounded-md px-2.5 py-1.5 text-xs text-[#252B33] focus:outline-none focus:border-[#1677C8] shadow-subtle"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94A3B8]" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-white border border-[#DDE3EA] rounded-md pl-8 pr-3 py-1.5 text-xs text-[#252B33] placeholder-[#94A3B8] focus:outline-none focus:border-[#1677C8] w-48 shadow-subtle"
            />
          </div>
        </div>
      </div>

      {/* Correlated Alerts Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredAlerts.length === 0 ? (
          <div className="col-span-full p-12 text-center text-[#657180] bg-white border border-[#DDE3EA] rounded-xl text-xs shadow-card">
            No correlated incidents found matching current filters.
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isExpanded = expandedCards.has(alert.id);
            const eventCount = alert.supporting_event_ids?.length || alert.supporting_events?.length || 0;
            const priorityClass = getPriorityBadgeClass(alert.severity);

            return (
              <div 
                key={alert.id}
                className="bg-white border border-[#DDE3EA] hover:border-[#1677C8]/50 rounded-xl p-5 transition-all shadow-card hover:shadow-md flex flex-col justify-between"
              >
                <div>
                  {/* Top Priority Header */}
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${priorityClass}`}>
                      {(alert.severity || 'Medium').toUpperCase()} PRIORITY
                    </span>
                    <span className="font-mono text-xs text-[#1677C8] font-semibold">{alert.id}</span>
                  </div>

                  {/* Title */}
                  <h3 className="text-base font-bold text-[#252B33] mb-3">
                    {alert.title}
                  </h3>

                  {/* Metadata Attributes */}
                  <div className="space-y-1.5 text-xs text-[#475569] font-mono border-t border-b border-[#F0F3F6] py-2.5 my-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[#657180]">User:</span>
                      <strong className="text-[#1677C8]">{alert.primary_user || 'Not specified'}</strong>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[#657180]">Source IP:</span>
                      <strong className="text-[#252B33]">{alert.primary_ip || 'Not recorded'}</strong>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[#657180]">First observed:</span>
                      <span className="text-[#252B33]">{formatTimestamp(alert.first_seen)}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[#657180]">Related events:</span>
                      <strong className="text-[#252B33]">{eventCount} events</strong>
                    </div>
                  </div>

                  {/* Summary */}
                  <p className="text-xs text-[#475569] leading-relaxed line-clamp-2 my-2.5">
                    {alert.what_happened}
                  </p>

                  {/* Toggle details link */}
                  <button
                    type="button"
                    onClick={() => toggleCardExpand(alert.id)}
                    aria-expanded={isExpanded}
                    aria-controls={`correlation-details-${alert.id}`}
                    className="text-[11px] text-[#1677C8] hover:text-[#1366AC] font-medium flex items-center gap-1 mt-1 mb-2.5 transition focus:outline-none focus-visible:underline"
                  >
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    <span>{isExpanded ? 'Hide correlation details' : 'Show correlation details'}</span>
                  </button>

                  {/* Expanded Correlation Details Section — 7 Core Sections */}
                  {isExpanded && (
                    <div 
                      id={`correlation-details-${alert.id}`}
                      className="mb-3 p-3.5 bg-[#F8FAFC] border border-[#DDE3EA] rounded-lg text-xs space-y-3 animate-fadeIn shadow-inner"
                      role="region"
                      aria-label={`Correlation details for incident ${alert.id}`}
                    >
                      {/* 1. What happened? */}
                      <div>
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#1677C8] mb-0.5">
                          <Activity className="w-3 h-3 text-[#1677C8]" />
                          <span>1. What Happened?</span>
                        </div>
                        <p className="text-xs text-[#252B33] leading-relaxed">
                          {alert.what_happened || 'Incident telemetry correlated across multiple sequential events.'}
                        </p>
                      </div>

                      {/* 2. Why was it flagged? */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#DD6B20] mb-0.5">
                          <AlertTriangle className="w-3 h-3 text-[#DD6B20]" />
                          <span>2. Why Was It Flagged?</span>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[11px] text-[#475569]">
                            <strong className="text-[#252B33]">Rule:</strong> <span className="font-mono text-[#0F172A]">{alert.rule_id || 'Multi-Event Heuristic Rule'}</span>
                          </p>
                          <p className="text-[11px] text-[#475569] leading-relaxed">
                            <strong className="text-[#252B33]">Criteria:</strong> {alert.why_correlated || 'Correlated based on temporal proximity and shared entity identifiers.'}
                          </p>
                        </div>
                      </div>

                      {/* 3. Evidence summary */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#1677C8] mb-1">
                          <Database className="w-3 h-3 text-[#1677C8]" />
                          <span>3. Evidence Summary</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-[#475569] mb-1.5">
                          <span>Supporting events:</span>
                          <strong className="font-mono text-[#252B33] font-bold">{eventCount} events</strong>
                        </div>
                        {alert.supporting_event_ids && alert.supporting_event_ids.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {alert.supporting_event_ids.slice(0, 6).map((eid, idx) => (
                              <span 
                                key={idx} 
                                className="px-1.5 py-0.5 rounded bg-white border border-[#DDE3EA] font-mono text-[10px] text-[#252B33] shadow-subtle"
                              >
                                {eid}
                              </span>
                            ))}
                            {alert.supporting_event_ids.length > 6 && (
                              <span className="px-1.5 py-0.5 rounded bg-[#E2E8F0] text-[10px] text-[#64748B] font-mono font-semibold">
                                +{alert.supporting_event_ids.length - 6} more
                              </span>
                            )}
                          </div>
                        ) : (
                          <p className="text-[11px] text-[#94A3B8] italic">No event IDs linked</p>
                        )}
                      </div>

                      {/* 4. Related identities and assets */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#1677C8] mb-1">
                          <User className="w-3 h-3 text-[#1677C8]" />
                          <span>4. Related Identities & Assets</span>
                        </div>
                        <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
                          <div className="bg-white p-1.5 rounded border border-[#E2E8F0]">
                            <span className="text-[10px] text-[#657180] block font-sans">Account</span>
                            <span className="text-[#1677C8] font-semibold truncate block">{alert.primary_user || 'Not specified'}</span>
                          </div>
                          <div className="bg-white p-1.5 rounded border border-[#E2E8F0]">
                            <span className="text-[10px] text-[#657180] block font-sans">Source IP</span>
                            <span className="text-[#252B33] font-semibold truncate block">{alert.primary_ip || 'Not recorded'}</span>
                          </div>
                          <div className="bg-white p-1.5 rounded border border-[#E2E8F0]">
                            <span className="text-[10px] text-[#657180] block font-sans">Initial Host</span>
                            <span className="text-[#252B33] font-semibold truncate block">{alert.primary_host || 'Not specified'}</span>
                          </div>
                          <div className="bg-white p-1.5 rounded border border-[#E2E8F0]">
                            <span className="text-[10px] text-[#657180] block font-sans">Targeted Endpoints</span>
                            <span className="text-[#8B5CF6] font-semibold truncate block">
                              {alert.targeted_hosts && alert.targeted_hosts.length > 0 ? alert.targeted_hosts.join(', ') : 'None'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* 5. Time window */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#1677C8] mb-1">
                          <Clock className="w-3 h-3 text-[#1677C8]" />
                          <span>5. Observation Window</span>
                        </div>
                        <div className="text-[11px] text-[#475569] space-y-0.5 font-mono">
                          <div className="flex justify-between">
                            <span className="font-sans text-[#657180]">First observed:</span>
                            <span className="text-[#252B33]">{formatTimestamp(alert.first_seen)}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="font-sans text-[#657180]">Last observed:</span>
                            <span className="text-[#252B33]">{formatTimestamp(alert.last_seen)}</span>
                          </div>
                        </div>
                      </div>

                      {/* 6. What remains uncertain? */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#657180] mb-0.5">
                          <HelpCircle className="w-3 h-3 text-[#657180]" />
                          <span>6. What Remains Uncertain?</span>
                        </div>
                        <p className="text-[11px] text-[#475569] leading-relaxed">
                          {alert.what_remains_uncertain || 'Investigative hypothesis based on heuristics; requires verification against host process trees and external threat intelligence.'}
                        </p>
                      </div>

                      {/* 7. Recommended next step */}
                      <div className="pt-2 border-t border-[#E2E8F0]">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#16A34A] mb-0.5">
                          <CheckCircle className="w-3 h-3 text-[#16A34A]" />
                          <span>7. Recommended Next Step</span>
                        </div>
                        <p className="text-[11px] text-[#166534] bg-emerald-50 border border-emerald-200 rounded p-2 leading-relaxed">
                          {alert.recommended_actions && alert.recommended_actions.length > 0 
                            ? alert.recommended_actions[0] 
                            : `Verify account activity with user '${alert.primary_user || 'account holder'}' out-of-band and inspect recent IdP access records.`}
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Bottom Row Actions */}
                <div className="flex items-center justify-between gap-2 pt-3 border-t border-[#DDE3EA]">
                  {/* Secondary buttons */}
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => (onNavigateGraph ? onNavigateGraph(alert) : onNavigateTraceback(alert))}
                      className="px-2.5 py-1.5 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle group"
                      title="View Incident Activity Trend (Line Graph)"
                    >
                      <LineChart className="w-3.5 h-3.5 text-[#1677C8] group-hover:scale-110 transition-transform" />
                      <span className="hidden sm:inline font-medium">Graph</span>
                    </button>

                    <button
                      onClick={() => onCreateCase(alert)}
                      className="px-2.5 py-1.5 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle"
                      title="Create Investigation Case"
                    >
                      <FolderPlus className="w-3.5 h-3.5 text-[#1677C8]" />
                      <span className="hidden sm:inline">Case</span>
                    </button>

                    <button
                      onClick={() => onDownloadPdf(alert.id)}
                      className="px-2.5 py-1.5 rounded-md text-xs bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition flex items-center gap-1 shadow-subtle"
                      title="Download PDF Investigation Report"
                    >
                      <FileDown className="w-3.5 h-3.5 text-[#16A34A]" />
                      <span className="hidden sm:inline">PDF</span>
                    </button>
                  </div>

                  {/* Primary "Investigate Incident" Arrow Button */}
                  <button
                    onClick={() => handleStartInvestigation(alert)}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white shadow-sm transition flex items-center gap-1.5 group shrink-0"
                  >
                    <span>Investigate Incident</span>
                    <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-1" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
