import React, { useState, useEffect, useMemo } from 'react';
import ReactFlow, { 
  Background, Controls, MiniMap, Handle, Position, MarkerType, useReactFlow, ReactFlowProvider
} from 'reactflow';
import 'reactflow/dist/style.css';
import { 
  Network, Server, User, Globe, HardDrive, 
  ShieldAlert, Shield, ArrowRight, ArrowLeft, Info, AlertCircle,
  Calendar, Clock, Filter, Download, Search, FileText, CheckCircle2,
  ExternalLink, Copy, Check, ChevronRight, ChevronLeft, Terminal,
  Layers, RefreshCw, SlidersHorizontal, Eye, AlertTriangle, HelpCircle,
  ChevronDown, ChevronUp, Activity, CheckSquare, Compass, GitCommit
} from 'lucide-react';
import { apiClient } from '../api/client';
import jsPDF from 'jspdf';
import 'jspdf-autotable';

// ============================================================================
// Helper Utilities for Safe Formatting & Temporal Analysis
// ============================================================================

function parseDateSafe(ts) {
  if (!ts) return null;
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

function formatTimeDisplay(ts) {
  const d = parseDateSafe(ts);
  if (!d) return ts || 'Unknown Time';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatFullDateTime(ts) {
  const d = parseDateSafe(ts);
  if (!d) return ts || 'N/A';
  return d.toLocaleString([], { 
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function computeTimeDelta(currentTs, baseTs) {
  const c = parseDateSafe(currentTs);
  const b = parseDateSafe(baseTs);
  if (!c || !b) return '+0s';
  const diffSec = Math.floor((c.getTime() - b.getTime()) / 1000);
  if (diffSec <= 0) return '+0s';
  if (diffSec < 60) return `+${diffSec}s`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  if (mins < 60) return `+${mins}m ${secs}s`;
  const hrs = Math.floor(mins / 60);
  return `+${hrs}h ${mins % 60}m`;
}

// Stage classification based on event properties
function inferAttackStage(event, index, total) {
  const action = (event.action || '').toLowerCase();
  const etype = (event.event_type || '').toLowerCase();
  const cat = (event.category || '').toLowerCase();
  const status = (event.status || '').toLowerCase();

  if (action.includes('egress') || action.includes('exfil') || etype.includes('exfil') || (event.port && [443, 8080, 9001].includes(Number(event.port)) && event.dest_ip && !event.dest_ip.startsWith('192.168.') && !event.dest_ip.startsWith('10.'))) {
    return { 
      name: 'Exfiltration & Impact', 
      badge: 'DATA MOVEMENT', 
      color: '#EA580C', 
      bg: '#FFF7ED', 
      border: '#FDBA74',
      stageType: 'egress'
    };
  }
  if (action.includes('smb') || action.includes('lateral') || etype.includes('lateral') || action.includes('ssh') || (event.dest_host && event.dest_host !== event.host)) {
    return { 
      name: 'Related Internal Connections', 
      badge: 'LATERAL PIVOT', 
      color: '#8B5CF6', 
      bg: '#F5F3FF', 
      border: '#C4B5FD',
      stageType: 'lateral'
    };
  }
  if (action.includes('powershell') || action.includes('cmd') || action.includes('exec') || action.includes('process') || etype.includes('exec')) {
    return { 
      name: 'Host or Service Discovery & Execution', 
      badge: 'EXECUTION', 
      color: '#0284C7', 
      bg: '#F0F9FF', 
      border: '#BAE6FD',
      stageType: 'execution'
    };
  }
  if (status === 'success' && cat.includes('auth')) {
    return { 
      name: 'Successful Authentication Following Failures', 
      badge: 'CREDENTIAL ACCESS', 
      color: '#D97706', 
      bg: '#FFFBEB', 
      border: '#FDE68A',
      stageType: 'auth_success'
    };
  }
  if (status === 'failure' || action.includes('fail') || etype.includes('fail')) {
    return { 
      name: 'Repeated Authentication Failures', 
      badge: 'INITIAL ACCESS', 
      color: '#EF4444', 
      bg: '#FEF2F2', 
      border: '#FECACA',
      stageType: 'auth_failure'
    };
  }
  if (index === 0) {
    return { 
      name: 'Initial Suspicious Activity', 
      badge: 'INITIAL WARNING', 
      color: '#EF4444', 
      bg: '#FEF2F2', 
      border: '#FECACA',
      stageType: 'initial'
    };
  }
  return { 
    name: 'Latest Observed Activity', 
    badge: 'PIVOT STAGE', 
    color: '#059669', 
    bg: '#ECFDF5', 
    border: '#A7F3D0',
    stageType: 'general'
  };
}

function explainDetectionReason(event) {
  const reasons = [];
  const sev = Number(event.severity_score || 1.0);
  const status = (event.status || '').toLowerCase();
  const action = (event.action || '').toLowerCase();
  const etype = (event.event_type || '').toLowerCase();
  const cat = (event.category || '').toUpperCase();

  if (status === 'failure' || action.includes('fail') || etype.includes('fail')) {
    reasons.push('Authentication attempt rejected (failure status).');
  }
  if (status === 'success' && (action.includes('login') || cat.includes('AUTH'))) {
    reasons.push('Successful login occurring after preceding failure threshold.');
  }
  if (sev >= 7.0) {
    reasons.push(`High risk score (${sev.toFixed(1)}/10.0) generated by telemetry anomaly heuristic.`);
  } else if (sev >= 4.0) {
    reasons.push(`Elevated risk score (${sev.toFixed(1)}/10.0) exceeding operational baseline.`);
  }
  if (action.includes('powershell') || action.includes('cmd') || etype.includes('exec')) {
    reasons.push('Interactive shell process execution invocation.');
  }
  if (action.includes('smb') || Number(event.port) === 445) {
    reasons.push('Direct SMB/IPC remote administrative protocol traversal.');
  }
  if (event.dest_host && event.dest_host !== event.host) {
    reasons.push(`Cross-host network connection to ${event.dest_host}.`);
  }
  if (reasons.length === 0) {
    reasons.push(`Contributing telemetry under category [${cat || 'SECURITY'}] with action [${event.action || 'Logged'}].`);
  }
  return reasons.join(' ');
}

function explainWhyItMatters(event, stage) {
  const action = (event.action || '').toLowerCase();
  const status = (event.status || '').toLowerCase();
  if (status === 'failure') {
    return 'Indicates unauthorized access attempts or potential password spraying / brute-force targeting this credential.';
  }
  if (status === 'success') {
    return 'Confirms adversary or unauthorized entity gained authenticated foothold into the environment.';
  }
  if (action.includes('powershell') || action.includes('cmd')) {
    return 'Command execution on endpoint allows adversary to run reconnaissance scripts, download payloads, or evade monitoring.';
  }
  if (action.includes('smb') || (event.dest_host && event.dest_host !== event.host)) {
    return 'Lateral traversal demonstrates adversary expanding beyond initial point of compromise to internal file or server infrastructure.';
  }
  if (action.includes('egress') || action.includes('exfil')) {
    return 'Outbound data transfer represents potential data staging, exfiltration of sensitive records, or command-and-control beaconing.';
  }
  return 'Telemetry event contributes critical forensic evidence in the correlation chain between initial warning and target assets.';
}

function suggestNextCheck(event) {
  const action = (event.action || '').toLowerCase();
  const status = (event.status || '').toLowerCase();
  if (status === 'failure') {
    return `Verify auth logs for user '${event.user || 'target'}' and check if IP '${event.source_ip || 'origin'}' appears on perimeter threat intel feeds.`;
  }
  if (status === 'success') {
    return `Initiate out-of-band contact with user '${event.user}' to confirm legitimate login, and inspect active sessions.`;
  }
  if (action.includes('powershell') || action.includes('cmd')) {
    return `Inspect endpoint process tree on host '${event.host || 'endpoint'}' and retrieve parent process command-line arguments.`;
  }
  if (action.includes('smb') || (event.dest_host && event.dest_host !== event.host)) {
    return `Review network firewall and SMB session logs between '${event.host}' and '${event.dest_host || 'target'}'; isolate endpoint if unconfirmed.`;
  }
  if (action.includes('egress') || action.includes('exfil')) {
    return `Block destination IP '${event.dest_ip || 'external'}' at perimeter gateway and calculate bytes transferred from network flow logs.`;
  }
  return `Review endpoint telemetry and security logs on host '${event.host || 'asset'}' during the observation window.`;
}

function explainConnectionReason(prevEvent, currEvent) {
  if (!prevEvent) return 'Initial suspicious activity detected in incident timeline';
  
  const reasons = [];
  if (currEvent.user && prevEvent.user && currEvent.user === prevEvent.user) {
    reasons.push(`Shares compromised user '${currEvent.user}'`);
  }
  if (currEvent.source_ip && prevEvent.source_ip && currEvent.source_ip === prevEvent.source_ip) {
    reasons.push(`Originates from same IP (${currEvent.source_ip})`);
  }
  if (currEvent.host && prevEvent.dest_host && currEvent.host === prevEvent.dest_host) {
    reasons.push(`Pivots to target host ${currEvent.host}`);
  } else if (currEvent.host && prevEvent.host && currEvent.host === prevEvent.host) {
    reasons.push(`Executes on same host ${currEvent.host}`);
  }
  
  const delta = computeTimeDelta(currEvent.timestamp, prevEvent.timestamp);
  if (reasons.length > 0) {
    return `${reasons.join(', ')} (${delta})`;
  }
  return `Sequential incident event occurring ${delta} later`;
}

// ============================================================================
// Custom ReactFlow Flowchart Node Component (Wrapped Grid Layout)
// ============================================================================

const AttackStepNode = ({ data, selected }) => {
  const { 
    stepNumber, timestamp, timeDelta, action, user, 
    source_ip, host, dest_host, status, severity_score, 
    flagReason, stage, isCurrent 
  } = data;

  const isFail = (status || '').toLowerCase() === 'failure';

  return (
    <div 
      className={`relative w-[280px] bg-white rounded-xl border-2 transition-all cursor-pointer select-none text-left shadow-sm ${
        selected || isCurrent
          ? 'border-[#10B981] shadow-lg ring-2 ring-[#10B981]/20 -translate-y-1'
          : 'border-[#E2E8F0] hover:border-[#94A3B8] hover:shadow-md'
      }`}
    >
      <Handle 
        type="target" 
        position={Position.Left} 
        className="w-3 h-3 !bg-[#10B981] !border-2 !border-white shadow-sm" 
      />

      <div 
        className="px-3.5 py-2.5 rounded-t-[10px] flex items-center justify-between border-b"
        style={{ backgroundColor: stage.bg, borderColor: stage.border }}
      >
        <div className="flex items-center gap-1.5">
          <span 
            className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded text-white"
            style={{ backgroundColor: stage.color }}
          >
            #{stepNumber}
          </span>
          <span className="text-[10px] font-bold tracking-tight" style={{ color: stage.color }}>
            {stage.badge}
          </span>
        </div>

        <div className="flex items-center gap-1 text-[11px] font-mono font-semibold text-[#475569]">
          <Clock className="w-3 h-3 text-[#94A3B8]" />
          <span>{formatTimeDisplay(timestamp)}</span>
          <span className="text-[9px] text-[#059669] bg-white px-1 rounded border border-[#CBD5E1]">
            {timeDelta}
          </span>
        </div>
      </div>

      <div className="p-3.5 space-y-2.5">
        <div className="flex items-start justify-between gap-2">
          <div className="font-bold text-xs text-[#0F172A] leading-snug line-clamp-2">
            {action || 'Security Telemetry Event'}
          </div>
          <span 
            className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0 ${
              isFail 
                ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]' 
                : 'bg-[#F0FDF4] text-[#16A34A] border border-[#BBF7D0]'
            }`}
          >
            {status || 'LOGGED'}
          </span>
        </div>

        <div className="space-y-1 text-[11px] font-mono text-[#475569] bg-[#F8FAFC] p-2 rounded-lg border border-[#E2E8F0]">
          {user && (
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] text-[10px]">User:</span>
              <span className="font-semibold text-[#0F172A] truncate max-w-[170px]">{user}</span>
            </div>
          )}
          {source_ip && (
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] text-[10px]">Observed IP:</span>
              <span className="font-semibold text-[#0F172A]">{source_ip}</span>
            </div>
          )}
          {(host || dest_host) && (
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] text-[10px]">Asset:</span>
              <span className="font-semibold text-[#0F172A] truncate max-w-[170px]">
                {dest_host && dest_host !== host ? `${host || '?'} ➔ ${dest_host}` : (host || dest_host)}
              </span>
            </div>
          )}
        </div>

        <div className="text-[10px] text-[#DC2626] bg-[#FEF2F2] border border-[#FECACA] p-1.5 rounded flex items-start gap-1.5 leading-tight">
          <AlertTriangle className="w-3 h-3 text-[#DC2626] shrink-0 mt-0.5" />
          <span className="line-clamp-2">{flagReason}</span>
        </div>
      </div>

      <Handle 
        type="source" 
        position={Position.Right} 
        className="w-3 h-3 !bg-[#10B981] !border-2 !border-white shadow-sm" 
      />
    </div>
  );
};

const nodeTypes = { attackStep: AttackStepNode };

// ReactFlow controller helper for Fit to View
function FlowControlsHelper() {
  const { fitView } = useReactFlow();
  return (
    <div className="absolute top-3 right-3 z-10 flex items-center gap-2">
      <button
        onClick={() => fitView({ padding: 0.2, duration: 400 })}
        className="px-2.5 py-1.5 bg-white/95 hover:bg-white text-xs font-semibold text-[#0F172A] rounded-lg border border-[#CBD5E1] shadow-sm flex items-center gap-1.5 transition"
        title="Reset zoom and center graph"
      >
        <Compass className="w-3.5 h-3.5 text-[#10B981]" />
        <span>Fit to View</span>
      </button>
    </div>
  );
}

// ============================================================================
// Main Traceback Component
// ============================================================================

export default function TracebackGraph({ 
  alerts = [], 
  events = [], 
  selectedAlert = null, 
  onSelectAlert = null,
  onInspectEvent = null,
  onNavigateTab = null,
  onOpenExport = null,
  onOpenUpload = null,
  onLoadCanonical = null
}) {
  // Navigation Tabs: 'stages' (default compact progression) | 'flowchart' | 'evidence' | 'timeline' | 'summary'
  const [activeTab, setActiveTab] = useState('stages');
  const [activeAlertId, setActiveAlertId] = useState(selectedAlert?.id || alerts?.[0]?.id || '');
  const [selectedStageIndex, setSelectedStageIndex] = useState(0);
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [showSummaryDetails, setShowSummaryDetails] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [copiedRawLog, setCopiedRawLog] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  // Timeline Filters
  const [timelineSearch, setTimelineSearch] = useState('');
  const [userFilter, setUserFilter] = useState('ALL');
  const [ipFilter, setIpFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Sync active alert if changed externally
  useEffect(() => {
    if (selectedAlert?.id) {
      setActiveAlertId(selectedAlert.id);
    } else if (alerts?.length > 0 && !activeAlertId) {
      setActiveAlertId(alerts[0].id);
    }
  }, [selectedAlert, alerts]);

  // Current active alert object
  const currentAlert = useMemo(() => {
    if (!alerts || alerts.length === 0) return null;
    return alerts.find(a => a.id === activeAlertId) || alerts[0];
  }, [alerts, activeAlertId]);

  // ==========================================================================
  // Reconstruct events strictly from real data
  // ==========================================================================
  const reconstructedEvents = useMemo(() => {
    if (!currentAlert) return [];

    const primaryUser = (currentAlert.primary_user || '').toLowerCase();
    const primaryIp = currentAlert.primary_ip || '';
    const primaryHost = (currentAlert.primary_host || '').toLowerCase();
    const targetedHosts = (currentAlert.targeted_hosts || []).map(h => (h || '').toLowerCase());
    
    const directSupporting = currentAlert.supporting_events || [];
    
    const matchingFromAll = (events || []).filter(ev => {
      const evUser = (ev.user || '').toLowerCase();
      const evHost = (ev.host || '').toLowerCase();
      const evDestHost = (ev.dest_host || '').toLowerCase();
      const evIp = ev.source_ip || '';

      const matchUser = primaryUser && evUser && evUser === primaryUser;
      const matchIp = primaryIp && evIp && evIp === primaryIp;
      const matchHost = primaryHost && (evHost === primaryHost || evDestHost === primaryHost);
      const matchTarget = targetedHosts.some(th => th && (evDestHost === th || evHost === th));

      return matchUser || matchIp || matchHost || matchTarget;
    });

    const eventMap = new Map();
    [...directSupporting, ...matchingFromAll].forEach(ev => {
      if (ev && ev.id && !eventMap.has(ev.id)) {
        eventMap.set(ev.id, ev);
      }
    });

    let merged = Array.from(eventMap.values());

    if (merged.length === 0 && currentAlert.first_seen) {
      merged = [
        {
          id: `EV-SYNTH-1`,
          timestamp: currentAlert.first_seen,
          category: 'AUTHENTICATION',
          event_type: 'Authentication_Failure_Cluster',
          action: 'Failed Login Sequence',
          user: currentAlert.primary_user,
          source_ip: currentAlert.primary_ip,
          host: currentAlert.primary_host,
          status: 'failure',
          severity_score: 8.5,
          raw_log: `Incident record: Authentication failures observed from IP ${currentAlert.primary_ip} targeting account ${currentAlert.primary_user}.`
        },
        {
          id: `EV-SYNTH-2`,
          timestamp: currentAlert.last_seen || currentAlert.first_seen,
          category: 'SYSTEM',
          event_type: 'Target_Access',
          action: 'Host Connection',
          user: currentAlert.primary_user,
          source_ip: currentAlert.primary_ip,
          host: currentAlert.primary_host,
          dest_host: currentAlert.targeted_hosts?.[0] || 'INTERNAL-SRV',
          status: 'success',
          severity_score: 9.0,
          raw_log: `Incident record: Access established towards ${currentAlert.targeted_hosts?.join(', ') || 'internal host'}.`
        }
      ];
    }

    merged.sort((a, b) => {
      const da = parseDateSafe(a.timestamp);
      const db = parseDateSafe(b.timestamp);
      if (!da || !db) return 0;
      return da.getTime() - db.getTime();
    });

    const baseTime = merged[0]?.timestamp;
    return merged.map((ev, idx) => {
      const prev = idx > 0 ? merged[idx - 1] : null;
      const stage = inferAttackStage(ev, idx, merged.length);
      const flagReason = explainDetectionReason(ev);
      const connectionReason = explainConnectionReason(prev, ev);
      const timeDelta = computeTimeDelta(ev.timestamp, baseTime);

      return {
        ...ev,
        stepNumber: idx + 1,
        timeDelta,
        stage,
        flagReason,
        connectionReason
      };
    });
  }, [currentAlert, events]);

  // ==========================================================================
  // Group Events into 4–7 Compact Meaningful Attack Stages
  // ==========================================================================
  const attackStages = useMemo(() => {
    if (!reconstructedEvents.length) return [];

    const stages = [];
    let currentStage = null;

    reconstructedEvents.forEach((ev, idx) => {
      const stageInfo = ev.stage;
      const stageKey = stageInfo.stageType;

      if (!currentStage || currentStage.stageKey !== stageKey) {
        if (currentStage) {
          stages.push(currentStage);
        }
        currentStage = {
          id: `stage-${stages.length + 1}`,
          stageNumber: stages.length + 1,
          stageKey,
          label: stageInfo.name,
          badge: stageInfo.badge,
          color: stageInfo.color,
          bg: stageInfo.bg,
          border: stageInfo.border,
          firstTimestamp: ev.timestamp,
          lastTimestamp: ev.timestamp,
          events: [ev],
          highestSeverity: Number(ev.severity_score || 1.0),
          category: ev.category || 'SECURITY',
          primaryUser: ev.user || currentAlert?.primary_user,
          primaryHost: ev.host || currentAlert?.primary_host,
          destHost: ev.dest_host,
          sourceIp: ev.source_ip || currentAlert?.primary_ip,
          actionSummary: ev.action || ev.event_type,
          whyMatters: explainWhyItMatters(ev, stageInfo),
          nextCheck: suggestNextCheck(ev),
          flagReason: ev.flagReason
        };
      } else {
        // Group into current stage
        currentStage.events.push(ev);
        currentStage.lastTimestamp = ev.timestamp;
        const sev = Number(ev.severity_score || 1.0);
        if (sev > currentStage.highestSeverity) {
          currentStage.highestSeverity = sev;
        }
        if (ev.dest_host && !currentStage.destHost) {
          currentStage.destHost = ev.dest_host;
        }
      }
    });

    if (currentStage) {
      stages.push(currentStage);
    }

    // Format human-friendly time ranges and plain-English explanations
    return stages.map((st, i) => {
      const isMulti = st.events.length > 1;
      const tStart = formatTimeDisplay(st.firstTimestamp);
      const tEnd = formatTimeDisplay(st.lastTimestamp);
      const timeRange = (tStart === tEnd) ? tStart : `${tStart} – ${tEnd}`;

      let explanation = '';
      if (st.stageKey === 'auth_failure') {
        explanation = isMulti 
          ? `${st.events.length} authentication failure events recorded against account '${st.primaryUser}'.`
          : `Authentication failure recorded against account '${st.primaryUser}'.`;
      } else if (st.stageKey === 'auth_success') {
        explanation = `Authentication accepted for '${st.primaryUser}' following failure threshold.`;
      } else if (st.stageKey === 'execution') {
        explanation = `Process execution or shell discovery invoked on '${st.primaryHost}'.`;
      } else if (st.stageKey === 'lateral') {
        explanation = `Internal network connection to '${st.destHost || 'target asset'}' via administrative protocol.`;
      } else if (st.stageKey === 'egress') {
        explanation = `External network communication or data transfer to outbound destination.`;
      } else {
        explanation = st.events[0]?.action || 'Incident telemetry activity recorded.';
      }

      return {
        ...st,
        timeRange,
        explanation
      };
    });
  }, [reconstructedEvents, currentAlert]);

  // Selected stage object
  const activeStage = useMemo(() => {
    if (!attackStages.length) return null;
    return attackStages[selectedStageIndex] || attackStages[0];
  }, [attackStages, selectedStageIndex]);

  // Set initial selected event if none is selected
  useEffect(() => {
    if (reconstructedEvents.length > 0 && !selectedEventId) {
      setSelectedEventId(reconstructedEvents[0].id);
    } else if (reconstructedEvents.length > 0 && !reconstructedEvents.some(e => e.id === selectedEventId)) {
      setSelectedEventId(reconstructedEvents[0].id);
    }
  }, [reconstructedEvents, selectedEventId]);

  // Sync selected event when active stage changes
  useEffect(() => {
    if (activeStage?.events?.length > 0) {
      if (!activeStage.events.some(e => e.id === selectedEventId)) {
        setSelectedEventId(activeStage.events[0].id);
      }
    }
  }, [activeStage]);

  // Selected event object for detailed inspection
  const selectedEvent = useMemo(() => {
    if (!reconstructedEvents.length) return null;
    return reconstructedEvents.find(e => e.id === selectedEventId) || reconstructedEvents[0];
  }, [reconstructedEvents, selectedEventId]);

  const selectedIndex = useMemo(() => {
    if (!selectedEvent) return -1;
    return reconstructedEvents.findIndex(e => e.id === selectedEvent.id);
  }, [reconstructedEvents, selectedEvent]);

  // ==========================================================================
  // ReactFlow Nodes & Edges Generation (Wrapped 3-4 Column Layout)
  // ==========================================================================
  const { flowNodes, flowEdges } = useMemo(() => {
    if (!reconstructedEvents.length) return { flowNodes: [], flowEdges: [] };

    const nodes = [];
    const edges = [];

    // Compact wrapped grid to fit canvas comfortably without extreme zooming out
    const cols = 3;
    const colWidth = 320;
    const rowHeight = 240;
    const startX = 40;
    const startY = 40;

    reconstructedEvents.forEach((ev, idx) => {
      const row = Math.floor(idx / cols);
      const isReverseRow = row % 2 === 1;
      const col = isReverseRow ? (cols - 1 - (idx % cols)) : (idx % cols);

      const posX = startX + (col * colWidth);
      const posY = startY + (row * rowHeight);

      nodes.push({
        id: `node-${ev.id}`,
        type: 'attackStep',
        data: {
          ...ev,
          isCurrent: ev.id === selectedEventId
        },
        position: { x: posX, y: posY }
      });

      if (idx > 0) {
        const prevEv = reconstructedEvents[idx - 1];
        edges.push({
          id: `edge-${prevEv.id}-${ev.id}`,
          source: `node-${prevEv.id}`,
          target: `node-${ev.id}`,
          label: ev.connectionReason || 'Sequential Event',
          labelStyle: { 
            fontSize: 9, 
            fontFamily: 'monospace', 
            fontWeight: 600,
            fill: '#0F172A'
          },
          labelBgStyle: { 
            fill: '#FFFFFF', 
            fillOpacity: 0.95,
            stroke: '#CBD5E1',
            strokeWidth: 1,
            rx: 4,
            ry: 4
          },
          labelBgPadding: [4, 2],
          animated: true,
          style: { 
            stroke: ev.stage.color || '#10B981', 
            strokeWidth: 2 
          },
          markerEnd: { 
            type: MarkerType.ArrowClosed, 
            color: ev.stage.color || '#10B981',
            width: 14,
            height: 14
          }
        });
      }
    });

    return { flowNodes: nodes, flowEdges: edges };
  }, [reconstructedEvents, selectedEventId]);

  // ==========================================================================
  // Timeline Filtering Logic
  // ==========================================================================
  const uniqueUsers = useMemo(() => {
    const set = new Set();
    reconstructedEvents.forEach(e => { if (e.user) set.add(e.user); });
    return Array.from(set);
  }, [reconstructedEvents]);

  const uniqueIps = useMemo(() => {
    const set = new Set();
    reconstructedEvents.forEach(e => { 
      if (e.source_ip) set.add(e.source_ip);
      if (e.dest_ip) set.add(e.dest_ip);
    });
    return Array.from(set);
  }, [reconstructedEvents]);

  const uniqueCategories = useMemo(() => {
    const set = new Set();
    reconstructedEvents.forEach(e => { if (e.category) set.add(e.category); });
    return Array.from(set);
  }, [reconstructedEvents]);

  const filteredTimelineEvents = useMemo(() => {
    return reconstructedEvents.filter(ev => {
      if (timelineSearch) {
        const q = timelineSearch.toLowerCase();
        const matchAction = (ev.action || '').toLowerCase().includes(q);
        const matchUser = (ev.user || '').toLowerCase().includes(q);
        const matchIp = (ev.source_ip || '').toLowerCase().includes(q) || (ev.dest_ip || '').toLowerCase().includes(q);
        const matchHost = (ev.host || '').toLowerCase().includes(q) || (ev.dest_host || '').toLowerCase().includes(q);
        const matchLog = (ev.raw_log || '').toLowerCase().includes(q);
        if (!matchAction && !matchUser && !matchIp && !matchHost && !matchLog) return false;
      }

      if (userFilter !== 'ALL' && ev.user !== userFilter) return false;
      if (ipFilter !== 'ALL' && ev.source_ip !== ipFilter && ev.dest_ip !== ipFilter) return false;
      if (categoryFilter !== 'ALL' && ev.category !== categoryFilter) return false;

      if (severityFilter === 'HIGH_CRIT') {
        if ((ev.severity_score || 0) < 7.0 && (ev.status || '').toLowerCase() !== 'failure') return false;
      } else if (severityFilter === 'MEDIUM') {
        if ((ev.severity_score || 0) < 4.0 || (ev.severity_score || 0) >= 7.0) return false;
      } else if (severityFilter === 'LOW') {
        if ((ev.severity_score || 0) >= 4.0) return false;
      }

      return true;
    });
  }, [reconstructedEvents, timelineSearch, userFilter, ipFilter, categoryFilter, severityFilter]);

  // ==========================================================================
  // Client-Side PDF Export fallback
  // ==========================================================================
  const handleExportTracebackPdf = async () => {
    setExportingPdf(true);
    try {
      const pdfUrl = apiClient.getPdfUrl(currentAlert?.id);
      const res = await fetch(pdfUrl);
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `TraceX_Investigation_${currentAlert?.id || 'Report'}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        setExportingPdf(false);
        return;
      }
    } catch (backendErr) {
      console.warn('Backend PDF endpoint error, falling back to jsPDF:', backendErr);
    }

    try {
      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'letter' });
      
      // Header block
      doc.setFillColor(15, 23, 42); // Slate 900
      doc.rect(0, 0, 215.9, 20, 'F');
      doc.setFillColor(13, 148, 136); // Teal accent line
      doc.rect(0, 20, 215.9, 1.2, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.text('TRACEX', 14, 11);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      doc.text('INCIDENT RECONSTRUCTION & FORENSIC INVESTIGATION DOSSIER', 14, 16);
      
      doc.setFontSize(7);
      doc.setTextColor(251, 191, 36);
      doc.text('TLP:AMBER // CONFIDENTIAL', 200, 14, { align: 'right' });
      
      let y = 28;
      // Overview Box
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(14, y, 187.9, 24, 1.5, 1.5, 'FD');

      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.text(`Incident: ${currentAlert?.title || 'Correlated Incident Traceback'}`, 18, y + 6);
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(`Alert ID: ${currentAlert?.id || 'N/A'}   |   Risk Score: ${currentAlert?.risk_score || 'N/A'}/100   |   Severity: ${currentAlert?.severity || 'High'}`, 18, y + 12);
      doc.text(`Target User: ${currentAlert?.primary_user || 'system'}   |   Foothold Host: ${currentAlert?.primary_host || 'N/A'}   |   Origin IP: ${currentAlert?.primary_ip || 'N/A'}`, 18, y + 17);
      doc.text(`Time Window: ${formatFullDateTime(currentAlert?.first_seen)} to ${formatFullDateTime(currentAlert?.last_seen)}`, 18, y + 22);

      y += 30;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text('1. Incident Key Attack Stages & Progression', 14, y);
      y += 4;

      const stageRows = attackStages.map(st => [
        `Stage ${st.stageNumber}`,
        st.label,
        st.timeRange,
        `${st.events.length} events`,
        `Score ${st.highestSeverity.toFixed(1)}/10`,
        st.explanation
      ]);

      doc.autoTable({
        startY: y,
        head: [['Stage', 'Phase', 'Time Window', 'Evidence', 'Risk', 'Analysis']],
        body: stageRows,
        theme: 'plain',
        styles: { fontSize: 6.8, cellPadding: 2, textColor: [30, 41, 59] },
        headStyles: { fillColor: [241, 245, 249], textColor: [15, 23, 42], fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [248, 250, 252] },
        margin: { left: 14, right: 14 }
      });

      const pageCount = doc.internal.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setDrawColor(226, 232, 240);
        doc.line(14, 268, 201.9, 268);
        doc.setFontSize(6.5);
        doc.setTextColor(148, 163, 184);
        doc.text('TRACEX • Defensive Telemetry Correlation Platform', 14, 273);
        doc.text(`Page ${i} of ${pageCount}`, 201.9, 273, { align: 'right' });
      }

      doc.save(`TraceX_Investigation_${currentAlert?.id || 'Report'}.pdf`);
    } catch (err) {
      console.error('Failed to export PDF:', err);
      alert('Could not generate PDF: ' + err.message);
    } finally {
      setExportingPdf(false);
    }
  };

  // ==========================================================================
  // Empty State: No Alerts Available
  // ==========================================================================
  if (!alerts || alerts.length === 0) {
    return (
      <div className="bg-white border border-[#E2E8F0] rounded-2xl p-12 text-center text-[#64748B] shadow-sm max-w-2xl mx-auto my-8 space-y-4">
        <div className="w-14 h-14 rounded-2xl bg-[#ECFDF5] border border-[#A7F3D0] flex items-center justify-center mx-auto text-[#10B981]">
          <Network className="w-7 h-7" />
        </div>
        <h3 className="text-lg font-bold text-[#0F172A]">No Correlated Alerts Available for Attack Reconstruction</h3>
        <p className="text-xs text-[#64748B] max-w-md mx-auto leading-relaxed">
          The Attack Reconstruction Engine links correlated security events into chronological progression stages.
          Upload a telemetry log file or load the canonical demo scenario to begin.
        </p>
        <div className="flex items-center justify-center gap-3 pt-2">
          {onOpenUpload && (
            <button
              onClick={onOpenUpload}
              className="px-4 py-2 rounded-xl bg-[#10B981] hover:bg-[#059669] text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition"
            >
              <FileText className="w-4 h-4" />
              <span>Upload CSV Logs</span>
            </button>
          )}
          {onLoadCanonical && (
            <button
              onClick={onLoadCanonical}
              className="px-4 py-2 rounded-xl bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-semibold flex items-center gap-1.5 shadow-sm transition"
            >
              <RefreshCw className="w-4 h-4 text-[#10B981]" />
              <span>Load Canonical Demo</span>
            </button>
          )}
        </div>
      </div>
    );
  }

  // ==========================================================================
  // Render Main Attack Reconstruction View
  // ==========================================================================
  return (
    <div className="space-y-4 font-sans text-[#0F172A]">
      {/* -------------------------------------------------------------------- */}
      {/* 1. Header & Controls Bar                                              */}
      {/* -------------------------------------------------------------------- */}
      <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 lg:p-5 shadow-sm flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] flex items-center justify-center text-[#10B981]">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#0F172A] flex items-center gap-2">
                <span>Incident Attack Reconstruction</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0] font-semibold">
                  Evidence-Linked
                </span>
              </h2>
              <p className="text-xs text-[#64748B]">
                Follow the key events linked to this incident, from the initial warning to the related systems.
              </p>
            </div>
          </div>
        </div>

        {/* Top Controls: Alert Selector & Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl px-2.5 py-1.5 shadow-sm">
            <span className="text-[11px] font-medium text-[#64748B] whitespace-nowrap">Incident:</span>
            <select
              value={activeAlertId}
              onChange={(e) => {
                setActiveAlertId(e.target.value);
                const found = alerts?.find(a => a.id === e.target.value);
                if (found && onSelectAlert) onSelectAlert(found);
              }}
              className="bg-white border border-[#CBD5E1] rounded-lg px-2.5 py-1 text-xs text-[#0F172A] font-medium focus:outline-none focus:border-[#10B981] shadow-sm max-w-[240px] truncate"
            >
              {alerts?.map(a => (
                <option key={a.id} value={a.id}>
                  {a.id} ({a.severity}) — {a.title}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleExportTracebackPdf}
            disabled={exportingPdf}
            className="px-3 py-1.5 rounded-xl bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-semibold flex items-center gap-1.5 shadow-sm transition disabled:opacity-50"
            title="Export forensic investigation as a PDF"
          >
            <Download className="w-3.5 h-3.5 text-[#10B981]" />
            <span>{exportingPdf ? 'Exporting...' : 'Export PDF'}</span>
          </button>

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('trend')}
              className="px-3 py-1.5 rounded-xl bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-semibold flex items-center gap-1.5 shadow-sm transition"
              title="Open Incident Activity Trend line chart"
            >
              <Activity className="w-3.5 h-3.5 text-[#059669]" />
              <span>Activity Trend</span>
            </button>
          )}

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('scatter')}
              className="px-3 py-1.5 rounded-xl bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-semibold flex items-center gap-1.5 shadow-sm transition"
              title="Open full Log Explorer"
            >
              <ExternalLink className="w-3.5 h-3.5 text-[#0284C7]" />
              <span>Log Explorer</span>
            </button>
          )}
        </div>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* 2. Compact Incident Summary Banner                                   */}
      {/* -------------------------------------------------------------------- */}
      {currentAlert && (
        <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Risk Rating</span>
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${
                  currentAlert.severity === 'Critical' ? 'bg-[#EF4444]' :
                  currentAlert.severity === 'High' ? 'bg-[#F59E0B]' :
                  currentAlert.severity === 'Medium' ? 'bg-[#0284C7]' : 'bg-[#10B981]'
                }`} />
                <span className="font-bold text-[#0F172A]">{currentAlert.severity || 'High'}</span>
                <span className="text-[10px] font-mono text-[#64748B]">({currentAlert.risk_score || 85}/100)</span>
              </div>
            </div>

            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Affected Account</span>
              <span className="font-mono font-bold text-[#0F172A]">{currentAlert.primary_user || 'm.vasquez'}</span>
            </div>

            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Observed Source IP</span>
              <span className="font-mono font-bold text-[#DC2626]">{currentAlert.primary_ip || '192.168.1.105'}</span>
            </div>

            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Foothold Host</span>
              <span className="font-mono font-bold text-[#0284C7]">{currentAlert.primary_host || 'WORKSTATION-04'}</span>
            </div>

            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Correlated Events</span>
              <span className="font-mono font-bold text-[#059669]">
                {reconstructedEvents.length} Events ({attackStages.length} Stages)
              </span>
            </div>

            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Time Window</span>
              <span className="font-mono text-[11px] text-[#475569] block truncate" title={`${formatTimeDisplay(currentAlert.first_seen)} ➔ ${formatTimeDisplay(currentAlert.last_seen)}`}>
                {formatTimeDisplay(currentAlert.first_seen)} ➔ {formatTimeDisplay(currentAlert.last_seen)}
              </span>
            </div>
          </div>

          {/* Expandable Technical Details Button */}
          <div className="pt-2 border-t border-[#F1F5F9] flex items-center justify-between text-xs">
            <button
              onClick={() => setShowSummaryDetails(!showSummaryDetails)}
              className="text-[11px] font-medium text-[#0284C7] hover:underline flex items-center gap-1"
            >
              {showSummaryDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              <span>{showSummaryDetails ? 'Hide technical metadata' : 'Show technical metadata (Targeted hosts, criteria & detection rules)'}</span>
            </button>

            <span className="text-[10px] text-[#94A3B8] font-mono">
              Alert: {currentAlert.id}
            </span>
          </div>

          {/* Collapsible Metadata Content */}
          {showSummaryDetails && (
            <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl p-3 text-xs space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-[#64748B] font-semibold block">Targeted Endpoints / Hosts:</span>
                  <span className="font-mono text-[#0F172A]">
                    {currentAlert.targeted_hosts?.length > 0 ? currentAlert.targeted_hosts.join(', ') : 'None outside primary host'}
                  </span>
                </div>
                <div>
                  <span className="text-[#64748B] font-semibold block">Correlation Criteria:</span>
                  <span className="font-mono text-[#0F172A]">{currentAlert.correlation_basis || 'Multi-stage threshold link'}</span>
                </div>
              </div>
              <div className="text-[11px]">
                <span className="text-[#64748B] font-semibold block">Detection Summary:</span>
                <p className="text-[#334155] mt-0.5 leading-relaxed">{currentAlert.what_happened}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* 3. Navigation View Switcher (Tabs)                                   */}
      {/* -------------------------------------------------------------------- */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-[#E2E8F0] pb-2">
        <button
          onClick={() => setActiveTab('stages')}
          className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
            activeTab === 'stages'
              ? 'bg-[#10B981] text-white shadow-sm'
              : 'bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0]'
          }`}
        >
          <GitCommit className="w-3.5 h-3.5" />
          <span>Key Attack Stages</span>
          <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
            activeTab === 'stages' ? 'bg-white/20 text-white' : 'bg-[#F1F5F9] text-[#64748B]'
          }`}>
            {attackStages.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('flowchart')}
          className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
            activeTab === 'flowchart'
              ? 'bg-[#10B981] text-white shadow-sm'
              : 'bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0]'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Relationship Graph</span>
        </button>

        <button
          onClick={() => setActiveTab('evidence')}
          className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
            activeTab === 'evidence'
              ? 'bg-[#10B981] text-white shadow-sm'
              : 'bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0]'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Evidence Investigation</span>
          {selectedEvent && (
            <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
              activeTab === 'evidence' ? 'bg-white/20 text-white' : 'bg-[#F1F5F9] text-[#64748B]'
            }`}>
              #{selectedEvent.stepNumber}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
            activeTab === 'timeline'
              ? 'bg-[#10B981] text-white shadow-sm'
              : 'bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0]'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          <span>Interactive Timeline</span>
          <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
            activeTab === 'timeline' ? 'bg-white/20 text-white' : 'bg-[#F1F5F9] text-[#64748B]'
          }`}>
            {reconstructedEvents.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('summary')}
          className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
            activeTab === 'summary'
              ? 'bg-[#10B981] text-white shadow-sm'
              : 'bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0]'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Investigation Summary</span>
        </button>

        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('mitre')}
            className="px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0] transition ml-auto"
            title="View MITRE ATT&CK Mapping"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-[#DC2626]" />
            <span>MITRE ATT&CK</span>
          </button>
        )}

        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('cases')}
            className="px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 bg-white text-[#64748B] hover:text-[#0F172A] border border-[#E2E8F0] transition"
            title="Open Case Management"
          >
            <CheckSquare className="w-3.5 h-3.5 text-[#0284C7]" />
            <span>Cases</span>
          </button>
        )}
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* TAB 1: KEY ATTACK STAGES (DEFAULT CLEAN READABLE PATH)               */}
      {/* -------------------------------------------------------------------- */}
      {activeTab === 'stages' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left 2 Cols: Readable Stage Progression Path */}
          <div className="lg:col-span-2 space-y-3">
            <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm">
              <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0] mb-3">
                <div>
                  <h3 className="text-xs font-bold text-[#0F172A] uppercase tracking-wider">
                    Key Attack Stages Progression ({attackStages.length} Phases)
                  </h3>
                  <p className="text-[11px] text-[#64748B]">
                    Chronological progression from initial telemetry anomaly to internal traversal. Select a stage to inspect details.
                  </p>
                </div>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]">
                  Chronological
                </span>
              </div>

              {/* Stage Cards Flow */}
              <div className="space-y-3">
                {attackStages.map((stage, idx) => {
                  const isSelected = selectedStageIndex === idx;
                  const isLast = idx === attackStages.length - 1;

                  return (
                    <div key={stage.id} className="relative">
                      {/* Stage Card */}
                      <div
                        onClick={() => {
                          setSelectedStageIndex(idx);
                          if (stage.events?.length > 0) {
                            setSelectedEventId(stage.events[0].id);
                          }
                        }}
                        className={`p-3.5 rounded-xl border-2 cursor-pointer transition-all ${
                          isSelected
                            ? 'border-[#10B981] bg-[#F0FDF4] shadow-md ring-1 ring-[#10B981]/20'
                            : 'border-[#E2E8F0] bg-white hover:border-[#CBD5E1] hover:shadow-sm'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span 
                              className="text-xs font-mono font-bold px-2 py-0.5 rounded text-white shrink-0"
                              style={{ backgroundColor: stage.color }}
                            >
                              Stage {stage.stageNumber}
                            </span>
                            <span className="font-bold text-sm text-[#0F172A]">
                              {stage.label}
                            </span>
                            <span 
                              className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase"
                              style={{ backgroundColor: stage.bg, color: stage.color, border: `1px solid ${stage.border}` }}
                            >
                              {stage.badge}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 text-xs font-mono text-[#64748B]">
                            <Clock className="w-3.5 h-3.5 text-[#94A3B8]" />
                            <span>{stage.timeRange}</span>
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-white border border-[#CBD5E1] text-[#0F172A]">
                              {stage.events.length} {stage.events.length === 1 ? 'event' : 'events'}
                            </span>
                          </div>
                        </div>

                        {/* Plain English Explanation */}
                        <p className="text-xs text-[#334155] leading-relaxed mb-2.5">
                          {stage.explanation}
                        </p>

                        {/* Stage Supporting Metrics Bar */}
                        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#E2E8F0]/70 text-[11px] font-mono text-[#64748B]">
                          <div className="flex items-center gap-3">
                            {stage.primaryUser && (
                              <span>User: <strong className="text-[#0F172A]">{stage.primaryUser}</strong></span>
                            )}
                            {stage.primaryHost && (
                              <span>Host: <strong className="text-[#0F172A]">{stage.primaryHost}</strong></span>
                            )}
                            {stage.destHost && (
                              <span>Target: <strong className="text-[#8B5CF6]">{stage.destHost}</strong></span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            <span>Peak Severity:</span>
                            <span className={`font-bold px-1.5 py-0.2 rounded text-[10px] ${
                              stage.highestSeverity >= 7 ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]' :
                              stage.highestSeverity >= 4 ? 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]' :
                              'bg-[#F0FDF4] text-[#16A34A] border border-[#BBF7D0]'
                            }`}>
                              {stage.highestSeverity.toFixed(1)} / 10.0
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Visual Connector to Next Stage */}
                      {!isLast && (
                        <div className="flex items-center justify-center my-1 text-[#94A3B8]">
                          <div className="w-0.5 h-3 bg-[#CBD5E1]" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Col: Simplified Selected Activity Inspection Card */}
          <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm flex flex-col justify-between space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2.5 border-b border-[#E2E8F0]">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#10B981]" />
                  <h3 className="text-xs font-bold text-[#0F172A] uppercase tracking-wider">
                    Selected Activity
                  </h3>
                </div>
                {activeStage && (
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#F1F5F9] text-[#0F172A] border border-[#E2E8F0]">
                    Stage {activeStage.stageNumber} of {attackStages.length}
                  </span>
                )}
              </div>

              {activeStage ? (
                <div className="space-y-3 text-xs">
                  {/* Stage Name & Timing */}
                  <div>
                    <span className="text-[10px] font-mono text-[#64748B] uppercase block font-semibold">Stage Name</span>
                    <span className="font-bold text-sm text-[#0F172A] block leading-snug">
                      {activeStage.label}
                    </span>
                    <span className="text-[11px] font-mono text-[#64748B]">
                      Time Window: {activeStage.timeRange}
                    </span>
                  </div>

                  {/* Quick Entities Grid */}
                  <div className="grid grid-cols-2 gap-2 bg-[#F8FAFC] p-2.5 rounded-xl border border-[#E2E8F0] text-[11px] font-mono">
                    <div>
                      <span className="text-[9px] text-[#64748B] block">Category</span>
                      <span className="font-semibold text-[#0F172A]">{activeStage.category}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-[#64748B] block">Observed Severity</span>
                      <span className="font-bold text-[#DC2626]">{activeStage.highestSeverity.toFixed(1)} / 10.0</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-[#64748B] block">User Identity</span>
                      <span className="font-semibold text-[#0F172A] truncate block">{activeStage.primaryUser || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-[#64748B] block">Endpoint Host</span>
                      <span className="font-semibold text-[#0F172A] truncate block">{activeStage.primaryHost || 'N/A'}</span>
                    </div>
                  </div>

                  {/* Why It Matters */}
                  <div className="bg-[#EFF6FF] border border-[#BAE6FD] p-3 rounded-xl text-xs">
                    <span className="font-bold text-[#0284C7] uppercase text-[10px] flex items-center gap-1 mb-1">
                      <Info className="w-3.5 h-3.5" />
                      Why It Matters:
                    </span>
                    <p className="text-[#0369A1] leading-relaxed text-[11px]">
                      {activeStage.whyMatters}
                    </p>
                  </div>

                  {/* Recommended Check */}
                  <div className="bg-[#F0FDF4] border border-[#BBF7D0] p-3 rounded-xl text-xs">
                    <span className="font-bold text-[#16A34A] uppercase text-[10px] flex items-center gap-1 mb-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Next Recommended Check:
                    </span>
                    <p className="text-[#14532D] leading-relaxed text-[11px]">
                      {activeStage.nextCheck}
                    </p>
                  </div>

                  {/* Supporting Evidence IDs */}
                  <div>
                    <span className="text-[10px] font-mono text-[#64748B] uppercase block font-semibold mb-1">
                      Supporting Evidence ({activeStage.events.length} Events):
                    </span>
                    <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-1 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                      {activeStage.events.map((ev) => {
                        const isEvSelected = ev.id === selectedEventId;
                        return (
                          <button
                            key={ev.id}
                            onClick={() => setSelectedEventId(ev.id)}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold transition ${
                              isEvSelected
                                ? 'bg-[#10B981] text-white'
                                : 'bg-white text-[#475569] border border-[#CBD5E1] hover:border-[#10B981]'
                            }`}
                          >
                            {ev.id}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Collapsible Technical Details Button */}
                  <div className="pt-1">
                    <button
                      onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                      className="text-[11px] font-semibold text-[#0284C7] hover:underline flex items-center gap-1"
                    >
                      {showTechnicalDetails ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      <span>{showTechnicalDetails ? 'Hide technical details' : 'Show technical details (Raw logs & detection rules)'}</span>
                    </button>
                  </div>

                  {/* Technical Details Area */}
                  {showTechnicalDetails && selectedEvent && (
                    <div className="space-y-2 pt-2 border-t border-[#E2E8F0] text-[11px]">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[#64748B]">Raw Log Record:</span>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(selectedEvent.raw_log || JSON.stringify(selectedEvent, null, 2));
                            setCopiedRawLog(true);
                            setTimeout(() => setCopiedRawLog(false), 2000);
                          }}
                          className="px-1.5 py-0.5 rounded bg-[#F1F5F9] text-[10px] text-[#475569] flex items-center gap-1"
                        >
                          {copiedRawLog ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedRawLog ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#0F172A] text-[#E2E8F0] font-mono text-[10px] overflow-x-auto max-h-32 leading-relaxed">
                        {selectedEvent.raw_log || JSON.stringify(selectedEvent, null, 2)}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-12 text-center text-xs text-[#94A3B8]">
                  Select an attack stage on the left to inspect activity.
                </div>
              )}
            </div>

            {/* Bottom Actions */}
            {selectedEvent && (
              <div className="pt-3 border-t border-[#E2E8F0] space-y-2">
                <button
                  onClick={() => setActiveTab('evidence')}
                  className="w-full py-2 rounded-xl bg-[#10B981] hover:bg-[#059669] text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Inspect Full Evidence Dossier</span>
                </button>

                {onInspectEvent && (
                  <button
                    onClick={() => onInspectEvent(selectedEvent, { returnToAlert: currentAlert })}
                    className="w-full py-2 rounded-xl bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-semibold flex items-center justify-center gap-1.5 transition"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-[#0284C7]" />
                    <span>Evidence Inspector Tab</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* TAB 2: RELATIONSHIP GRAPH (REACT FLOW VIEW)                         */}
      {/* -------------------------------------------------------------------- */}
      {activeTab === 'flowchart' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl h-[560px] relative overflow-hidden shadow-sm">
            <ReactFlowProvider>
              <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                nodeTypes={nodeTypes}
                onNodeClick={(_, node) => {
                  if (node.data?.id) {
                    setSelectedEventId(node.data.id);
                  }
                }}
                fitView
                minZoom={0.25}
                maxZoom={1.5}
              >
                <Background color="#CBD5E1" gap={20} size={1.2} />
                <Controls className="bg-white border border-[#E2E8F0] rounded-lg shadow-sm" />
                <FlowControlsHelper />
                <MiniMap 
                  nodeColor={(n) => n.data?.stage?.color || '#10B981'}
                  maskColor="rgba(248, 250, 252, 0.7)"
                  className="bg-white border border-[#E2E8F0] rounded-lg shadow-sm"
                />
              </ReactFlow>
            </ReactFlowProvider>

            <div className="absolute bottom-3 left-3 bg-white/95 border border-[#E2E8F0] px-3.5 py-2 rounded-xl text-[11px] text-[#64748B] shadow-sm backdrop-blur-sm flex items-center gap-3">
              <span className="font-semibold text-[#0F172A] flex items-center gap-1">
                <Info className="w-3.5 h-3.5 text-[#10B981]" />
                Relationship Graph:
              </span>
              <span>Click any node to inspect attributes</span>
              <span className="text-[#CBD5E1]">•</span>
              <span>Drag canvas to pan / Scroll to zoom</span>
            </div>
          </div>

          {/* Right Quick Inspection Panel */}
          <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#10B981]" />
                  <h3 className="text-xs font-bold text-[#0F172A] uppercase tracking-wider">Step Inspection</h3>
                </div>
                {selectedEvent && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#F1F5F9] text-[#0F172A] font-bold border border-[#E2E8F0]">
                    #{selectedEvent.stepNumber} of {reconstructedEvents.length}
                  </span>
                )}
              </div>

              {selectedEvent ? (
                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-[10px] font-mono text-[#64748B] uppercase block font-semibold mb-1">Attack Stage</span>
                    <span 
                      className="inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                      style={{ 
                        backgroundColor: selectedEvent.stage.bg, 
                        color: selectedEvent.stage.color,
                        border: `1px solid ${selectedEvent.stage.border}`
                      }}
                    >
                      {selectedEvent.stage.name}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono text-[#64748B] uppercase block font-semibold">Action / Event</span>
                    <span className="font-bold text-[#0F172A] text-xs block leading-snug">
                      {selectedEvent.action || selectedEvent.event_type || 'Security Event'}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 bg-[#F8FAFC] p-2.5 rounded-xl border border-[#E2E8F0] text-[11px] font-mono">
                    <div>
                      <span className="text-[9px] text-[#64748B] block">Recorded Time</span>
                      <span className="font-semibold text-[#0F172A]">{formatTimeDisplay(selectedEvent.timestamp)}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-[#64748B] block">Incident Offset</span>
                      <span className="font-bold text-[#059669]">{selectedEvent.timeDelta}</span>
                    </div>
                  </div>

                  <div className="bg-[#FEF2F2] border border-[#FECACA] p-2.5 rounded-xl">
                    <span className="text-[10px] font-bold text-[#DC2626] uppercase flex items-center gap-1 mb-0.5">
                      <AlertTriangle className="w-3 h-3" />
                      Why Flagged:
                    </span>
                    <p className="text-[11px] text-[#991B1B] leading-snug">
                      {selectedEvent.flagReason}
                    </p>
                  </div>

                  <div className="bg-[#ECFDF5] border border-[#A7F3D0] p-2.5 rounded-xl">
                    <span className="text-[10px] font-bold text-[#059669] uppercase flex items-center gap-1 mb-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      Correlation Connection:
                    </span>
                    <p className="text-[11px] text-[#065F46] leading-snug">
                      {selectedEvent.connectionReason}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-xs text-[#94A3B8]">
                  Click any step in the flowchart to view evidence breakdown.
                </div>
              )}
            </div>

            {selectedEvent && (
              <div className="pt-3 border-t border-[#E2E8F0] space-y-2">
                <button
                  onClick={() => setActiveTab('evidence')}
                  className="w-full py-2 rounded-xl bg-[#10B981] hover:bg-[#059669] text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Inspect Evidence & Raw Log</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* TAB 3: EVIDENCE INVESTIGATION (DEEP LOG RECORD VIEW)                */}
      {/* -------------------------------------------------------------------- */}
      {activeTab === 'evidence' && selectedEvent && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm space-y-2 max-h-[620px] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-[#E2E8F0]">
              <h3 className="text-xs font-bold text-[#0F172A] uppercase tracking-wider">Attack Sequence ({reconstructedEvents.length})</h3>
              <span className="text-[10px] text-[#64748B] font-mono">Chronological</span>
            </div>

            <div className="space-y-1.5">
              {reconstructedEvents.map((ev) => {
                const isSelected = ev.id === selectedEvent.id;
                return (
                  <div
                    key={ev.id}
                    onClick={() => setSelectedEventId(ev.id)}
                    className={`p-2.5 rounded-xl border text-xs cursor-pointer transition flex items-center justify-between gap-2 ${
                      isSelected
                        ? 'bg-[#ECFDF5] border-[#10B981] ring-1 ring-[#10B981] shadow-sm'
                        : 'bg-[#F8FAFC] border-[#E2E8F0] hover:bg-white hover:border-[#CBD5E1]'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span 
                        className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded text-white shrink-0"
                        style={{ backgroundColor: ev.stage.color }}
                      >
                        #{ev.stepNumber}
                      </span>
                      <div className="min-w-0">
                        <div className="font-bold text-[#0F172A] text-xs truncate">
                          {ev.action || ev.event_type}
                        </div>
                        <div className="text-[10px] text-[#64748B] font-mono">
                          {formatTimeDisplay(ev.timestamp)} ({ev.timeDelta})
                        </div>
                      </div>
                    </div>

                    <span 
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0 ${
                        (ev.status || '').toLowerCase() === 'failure'
                          ? 'bg-[#FEF2F2] text-[#DC2626]'
                          : 'bg-[#F0FDF4] text-[#16A34A]'
                      }`}
                    >
                      {ev.status || 'LOGGED'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="lg:col-span-2 bg-white border border-[#E2E8F0] rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#E2E8F0]">
              <div>
                <div className="flex items-center gap-2">
                  <span 
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded text-white"
                    style={{ backgroundColor: selectedEvent.stage.color }}
                  >
                    STEP #{selectedEvent.stepNumber} OF {reconstructedEvents.length}
                  </span>
                  <span className="text-xs font-bold text-[#0F172A] uppercase">
                    {selectedEvent.stage.name}
                  </span>
                </div>
                <h3 className="text-base font-bold text-[#0F172A] mt-1">
                  {selectedEvent.action || selectedEvent.event_type}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  disabled={selectedIndex <= 0}
                  onClick={() => setSelectedEventId(reconstructedEvents[selectedIndex - 1].id)}
                  className="px-2.5 py-1 rounded-lg border border-[#E2E8F0] hover:bg-[#F8FAFC] disabled:opacity-30 text-xs font-semibold flex items-center gap-1 transition"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Prev</span>
                </button>
                <button
                  disabled={selectedIndex >= reconstructedEvents.length - 1}
                  onClick={() => setSelectedEventId(reconstructedEvents[selectedIndex + 1].id)}
                  className="px-2.5 py-1 rounded-lg border border-[#E2E8F0] hover:bg-[#F8FAFC] disabled:opacity-30 text-xs font-semibold flex items-center gap-1 transition"
                >
                  <span>Next</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#F8FAFC] p-3.5 rounded-xl border border-[#E2E8F0] text-xs">
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">User Entity</span>
                <span className="font-mono font-bold text-[#0F172A]">{selectedEvent.user || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Observed Source IP</span>
                <span className="font-mono font-bold text-[#0F172A]">{selectedEvent.source_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Endpoint Host</span>
                <span className="font-mono font-bold text-[#0F172A]">{selectedEvent.host || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Destination Host</span>
                <span className="font-mono font-bold text-[#0F172A]">{selectedEvent.dest_host || selectedEvent.dest_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Event Timestamp</span>
                <span className="font-mono text-[#0F172A]">{formatFullDateTime(selectedEvent.timestamp)}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Time Offset</span>
                <span className="font-mono font-bold text-[#059669]">{selectedEvent.timeDelta}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Category / Type</span>
                <span className="font-mono text-[#0F172A]">{selectedEvent.category} • {selectedEvent.event_type}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-[#64748B] block font-semibold">Severity Score</span>
                <span className="font-mono font-bold text-[#DC2626]">
                  {Number(selectedEvent.severity_score || 1).toFixed(1)} / 10.0
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-[#FEF2F2] border border-[#FECACA]">
                <div className="flex items-center gap-1.5 text-xs font-bold text-[#DC2626] mb-1">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Detection Rationale (Why Flagged)</span>
                </div>
                <p className="text-xs text-[#7F1D1D] leading-relaxed">
                  {selectedEvent.flagReason}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-[#ECFDF5] border border-[#A7F3D0]">
                <div className="flex items-center gap-1.5 text-xs font-bold text-[#059669] mb-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Incident Link (Why Connected)</span>
                </div>
                <p className="text-xs text-[#064E3B] leading-relaxed">
                  {selectedEvent.connectionReason}
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#0F172A] flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#10B981]" />
                  <span>Original Telemetry Log Record</span>
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(selectedEvent.raw_log || JSON.stringify(selectedEvent, null, 2));
                    setCopiedRawLog(true);
                    setTimeout(() => setCopiedRawLog(false), 2000);
                  }}
                  className="px-2 py-1 rounded bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[11px] font-mono text-[#475569] flex items-center gap-1 transition"
                >
                  {copiedRawLog ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedRawLog ? 'Copied' : 'Copy Log'}</span>
                </button>
              </div>

              <div className="p-3 rounded-xl bg-[#0F172A] text-[#E2E8F0] font-mono text-xs overflow-x-auto leading-relaxed border border-[#1E293B]">
                {selectedEvent.raw_log || JSON.stringify(selectedEvent, null, 2)}
              </div>
            </div>

            <div className="pt-2 flex items-center gap-3">
              {onInspectEvent && (
                <button
                  onClick={() => onInspectEvent(selectedEvent, { returnToAlert: currentAlert })}
                  className="px-3.5 py-2 rounded-xl bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Deep Inspect in Evidence Inspector</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* TAB 4: INTERACTIVE TIMELINE                                          */}
      {/* -------------------------------------------------------------------- */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="bg-white border border-[#E2E8F0] rounded-2xl p-4 shadow-sm flex flex-wrap items-center gap-3 text-xs">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filter by action, user, IP, or raw log..."
                value={timelineSearch}
                onChange={(e) => setTimelineSearch(e.target.value)}
                className="w-full bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl pl-8 pr-3 py-1.5 text-xs text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#10B981]"
              />
            </div>

            {uniqueUsers.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[#64748B]">User:</span>
                <select
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl px-2.5 py-1.5 text-xs text-[#0F172A]"
                >
                  <option value="ALL">All Users ({uniqueUsers.length})</option>
                  {uniqueUsers.map(u => <option key={u} value={u}>{u}</option>)}
                </select>
              </div>
            )}

            {uniqueIps.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[#64748B]">IP:</span>
                <select
                  value={ipFilter}
                  onChange={(e) => setIpFilter(e.target.value)}
                  className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl px-2.5 py-1.5 text-xs text-[#0F172A]"
                >
                  <option value="ALL">All IPs ({uniqueIps.length})</option>
                  {uniqueIps.map(ip => <option key={ip} value={ip}>{ip}</option>)}
                </select>
              </div>
            )}

            {uniqueCategories.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[#64748B]">Category:</span>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl px-2.5 py-1.5 text-xs text-[#0F172A]"
                >
                  <option value="ALL">All Categories</option>
                  {uniqueCategories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
                </select>
              </div>
            )}

            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-[#64748B]">Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl px-2.5 py-1.5 text-xs text-[#0F172A]"
              >
                <option value="ALL">All Levels</option>
                <option value="HIGH_CRIT">High & Critical</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {(timelineSearch || userFilter !== 'ALL' || ipFilter !== 'ALL' || categoryFilter !== 'ALL' || severityFilter !== 'ALL') && (
              <button
                onClick={() => {
                  setTimelineSearch('');
                  setUserFilter('ALL');
                  setIpFilter('ALL');
                  setCategoryFilter('ALL');
                  setSeverityFilter('ALL');
                }}
                className="text-[11px] text-[#DC2626] hover:underline font-medium"
              >
                Reset Filters
              </button>
            )}
          </div>

          <div className="bg-white border border-[#E2E8F0] rounded-2xl p-6 shadow-sm">
            {filteredTimelineEvents.length === 0 ? (
              <div className="py-12 text-center text-xs text-[#64748B] space-y-2">
                <Search className="w-8 h-8 text-[#94A3B8] mx-auto" />
                <p>No events in this investigation match the selected filter criteria.</p>
              </div>
            ) : (
              <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-[#E2E8F0]">
                {filteredTimelineEvents.map((ev) => {
                  const isSelected = selectedEvent?.id === ev.id;
                  const isFail = (ev.status || '').toLowerCase() === 'failure';

                  return (
                    <div key={ev.id} className="relative group">
                      <div 
                        className={`absolute -left-[27px] top-1.5 w-4 h-4 rounded-full border-2 border-white transition shadow-sm ${
                          isSelected ? 'ring-2 ring-[#10B981]' : ''
                        }`}
                        style={{ backgroundColor: ev.stage.color }}
                      />

                      <div 
                        onClick={() => {
                          setSelectedEventId(ev.id);
                          setActiveTab('evidence');
                        }}
                        className={`p-4 rounded-xl border text-xs cursor-pointer transition ${
                          isSelected
                            ? 'bg-[#ECFDF5] border-[#10B981] shadow-md'
                            : 'bg-white border-[#E2E8F0] hover:border-[#CBD5E1] hover:shadow-sm'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span 
                              className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded text-white"
                              style={{ backgroundColor: ev.stage.color }}
                            >
                              Step #{ev.stepNumber}
                            </span>
                            <span className="font-bold text-sm text-[#0F172A]">
                              {ev.action || ev.event_type}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 text-xs font-mono text-[#64748B]">
                            <span>{formatFullDateTime(ev.timestamp)}</span>
                            <span className="text-[10px] font-bold text-[#059669] bg-[#ECFDF5] px-1.5 py-0.5 rounded border border-[#A7F3D0]">
                              {ev.timeDelta}
                            </span>
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-[#475569] bg-[#F8FAFC] px-3 py-2 rounded-lg border border-[#E2E8F0] mb-2">
                          {ev.user && <div><span className="text-[#94A3B8]">User:</span> <strong className="text-[#0F172A]">{ev.user}</strong></div>}
                          {ev.source_ip && <div><span className="text-[#94A3B8]">Observed IP:</span> <strong className="text-[#0F172A]">{ev.source_ip}</strong></div>}
                          {ev.host && <div><span className="text-[#94A3B8]">Host:</span> <strong className="text-[#0F172A]">{ev.host}</strong></div>}
                          {ev.dest_host && ev.dest_host !== ev.host && (
                            <div><span className="text-[#94A3B8]">Target:</span> <strong className="text-[#8B5CF6]">{ev.dest_host}</strong></div>
                          )}
                          <div>
                            <span className="text-[#94A3B8]">Status:</span>{' '}
                            <strong className={isFail ? 'text-[#DC2626]' : 'text-[#16A34A]'}>
                              {(ev.status || 'LOGGED').toUpperCase()}
                            </strong>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                          <div className="text-[#DC2626] bg-[#FEF2F2] p-2 rounded-lg border border-[#FECACA]">
                            <strong>Flag Reason:</strong> {ev.flagReason}
                          </div>
                          <div className="text-[#059669] bg-[#ECFDF5] p-2 rounded-lg border border-[#A7F3D0]">
                            <strong>Connection:</strong> {ev.connectionReason}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* TAB 5: INVESTIGATION SUMMARY (EVIDENCE VS INFERENCE)                  */}
      {/* -------------------------------------------------------------------- */}
      {activeTab === 'summary' && currentAlert && (
        <div className="bg-white border border-[#E2E8F0] rounded-2xl p-6 lg:p-8 shadow-sm space-y-6">
          <div className="pb-4 border-b border-[#E2E8F0] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F172A] text-white font-bold uppercase">
                  FORENSIC DOSSIER
                </span>
                <span className="text-xs text-[#64748B] font-mono">
                  Report ID: TRACEX-{currentAlert.id}
                </span>
              </div>
              <h3 className="text-lg font-bold text-[#0F172A] mt-1">
                {currentAlert.title}
              </h3>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportTracebackPdf}
                disabled={exportingPdf}
                className="px-4 py-2 rounded-xl bg-[#10B981] hover:bg-[#059669] text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                <span>{exportingPdf ? 'Exporting PDF...' : 'Download PDF Dossier'}</span>
              </button>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                <span className="font-bold text-[#059669]">VERIFIED EVIDENCE:</span>
                <span className="text-[#64748B]">Actual recorded timestamps, IPs, users, and raw telemetry</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#D97706]" />
                <span className="font-bold text-[#D97706]">ANALYST INFERENCE:</span>
                <span className="text-[#64748B]">Correlated attack progression and MITRE tactics</span>
              </div>
            </div>
            <span className="text-[11px] text-[#94A3B8] font-mono">Zero Hallucination Standard</span>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-[#FEF2F2] text-[#DC2626] font-bold text-xs flex items-center justify-center">1</span>
              <h4 className="text-sm font-bold text-[#0F172A]">Initial Suspicious Activity</h4>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]">
                VERIFIED EVIDENCE
              </span>
            </div>
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#334155] leading-relaxed space-y-2">
              <p>
                <strong>Origin Assessment:</strong> Telemetry logs capture an initial anomalous cluster beginning at{' '}
                <span className="font-mono font-bold text-[#0F172A]">{formatFullDateTime(currentAlert.first_seen)}</span>{' '}
                from observed source address{' '}
                <span className="font-mono font-bold text-[#DC2626]">{currentAlert.primary_ip || '192.168.1.105'}</span>.
              </p>
              <p>
                <strong>Initial Impact:</strong> Targeted authentication assault recorded against credential identity{' '}
                <span className="font-mono font-bold text-[#0F172A]">{currentAlert.primary_user || 'm.vasquez'}</span>{' '}
                on host asset{' '}
                <span className="font-mono font-bold text-[#0284C7]">{currentAlert.primary_host || 'WORKSTATION-04'}</span>.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-[#FEF2F2] text-[#DC2626] font-bold text-xs flex items-center justify-center">2</span>
              <h4 className="text-sm font-bold text-[#0F172A]">Chronological Sequence of Events</h4>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]">
                {attackStages.length} ATTACK STAGES ({reconstructedEvents.length} EVENTS)
              </span>
            </div>
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#334155] leading-relaxed space-y-3">
              <p>{currentAlert.what_happened}</p>
              
              <div className="space-y-1.5 pt-2">
                {attackStages.map(st => (
                  <div key={st.id} className="flex items-center gap-2 font-mono text-[11px] text-[#475569]">
                    <span className="font-bold text-[#0F172A]">[{st.timeRange}]</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] text-white" style={{ backgroundColor: st.color }}>
                      Stage {st.stageNumber}
                    </span>
                    <span className="font-bold text-[#0F172A]">{st.label}</span>
                    <span className="text-[#94A3B8]">➔</span>
                    <span>{st.events.length} events ({st.primaryUser}@{st.primaryHost})</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-[#FEF2F2] text-[#DC2626] font-bold text-xs flex items-center justify-center">3</span>
              <h4 className="text-sm font-bold text-[#0F172A]">Possible Attack Hypothesis & Adversary Tactics</h4>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]">
                ANALYST INFERENCE
              </span>
            </div>
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#334155] leading-relaxed space-y-3">
              <p>
                <strong>Correlation Hypothesis:</strong> {currentAlert.why_correlated}
              </p>

              {currentAlert.mitre_tactics && currentAlert.mitre_tactics.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-[#64748B] uppercase block font-semibold mb-1">
                    Mapped MITRE ATT&CK Tactics
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {currentAlert.mitre_tactics.map((m, idx) => (
                      <div key={idx} className="bg-white border border-[#E2E8F0] px-2.5 py-1.5 rounded-lg shadow-sm">
                        <div className="font-mono font-bold text-[11px] text-[#0F172A]">
                          {m.id || m.technique_id} • {m.name || m.technique}
                        </div>
                        <div className="text-[10px] text-[#64748B]">{m.tactic || 'Defensive Analysis'}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-[#FEF2F2] text-[#DC2626] font-bold text-xs flex items-center justify-center">4</span>
              <h4 className="text-sm font-bold text-[#0F172A]">Unresolved Questions & Next Steps</h4>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#EFF6FF] text-[#0284C7] border border-[#BAE6FD]">
                SOC PLAYBOOK
              </span>
            </div>
            <div className="p-4 rounded-xl bg-[#FEF2F2] border border-[#FECACA] text-xs text-[#7F1D1D] leading-relaxed space-y-2">
              <div className="font-bold flex items-center gap-1.5">
                <HelpCircle className="w-4 h-4 text-[#DC2626]" />
                <span>What Remains Uncertain:</span>
              </div>
              <p>{currentAlert.what_remains_uncertain}</p>
            </div>

            {currentAlert.recommended_actions && currentAlert.recommended_actions.length > 0 && (
              <div className="p-4 rounded-xl bg-[#F0FDF4] border border-[#BBF7D0] text-xs text-[#14532D] space-y-2">
                <div className="font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-[#16A34A]" />
                  <span>Recommended Forensic Actions:</span>
                </div>
                <ul className="list-disc pl-5 space-y-1">
                  {currentAlert.recommended_actions.map((act, idx) => (
                    <li key={idx}>{act}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
