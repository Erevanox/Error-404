import React, { useState } from 'react';
import { 
  X, ShieldAlert, AlertTriangle, CheckSquare, Square, 
  ExternalLink, Network, FileDown, FolderPlus, Activity, 
  Clock, User, Server, Shield, HelpCircle 
} from 'lucide-react';

export default function AlertDetailModal({ 
  alert, 
  onClose, 
  onInspectEvent, 
  onNavigateTraceback, 
  onCreateCase,
  onOpenPlaybooks,
  onDownloadPdf 
}) {
  if (!alert) return null;

  const [checklist, setChecklist] = useState({});

  const toggleCheck = (idx) => {
    setChecklist(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm overflow-y-auto">
      <div className="bg-white border border-[#DDE3EA] rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col my-auto text-[#252B33]">
        {/* Modal Header */}
        <div className="p-5 border-b border-[#DDE3EA] flex items-start justify-between gap-4 sticky top-0 bg-white/95 backdrop-blur-md z-10">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                alert.severity === 'Critical' ? 'bg-[#FDE8E8] text-[#C53030] border border-[#F8B4B4]' :
                alert.severity === 'High' ? 'bg-[#FEEBC8] text-[#DD6B20] border border-[#FBD38D]' :
                'bg-[#FEFCBF] text-[#B7791F] border border-[#FAF089]'
              }`}>
                {alert.severity} ({alert.risk_score} / 100)
              </span>
              <span className="font-mono text-xs text-[#1677C8] font-semibold">{alert.id}</span>
              <span className="text-xs text-[#657180] font-mono">Rule: {alert.rule_id}</span>
            </div>
            <h2 className="text-lg font-bold text-[#252B33] tracking-tight">
              {alert.title}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-[#657180] hover:text-[#252B33] bg-[#F0F3F6] hover:bg-[#E2E8F0] transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 flex-1 text-xs">
          {/* Metadata Pill Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-xl bg-[#F8FAFC] border border-[#DDE3EA]">
            <div>
              <span className="text-[10px] text-[#657180] uppercase font-mono block font-semibold">Target User</span>
              <span className="font-mono text-[#1677C8] font-semibold">{alert.primary_user || 'system'}</span>
            </div>
            <div>
              <span className="text-[10px] text-[#657180] uppercase font-mono block font-semibold">Origin Address</span>
              <span className="font-mono text-[#252B33] font-semibold">{alert.primary_ip || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] text-[#657180] uppercase font-mono block font-semibold">Initial Asset</span>
              <span className="font-mono text-[#252B33] font-semibold">{alert.primary_host || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] text-[#657180] uppercase font-mono block font-semibold">Observation Window</span>
              <span className="font-mono text-[#DD6B20] font-semibold">
                {alert.first_seen?.substring(11, 19)} - {alert.last_seen?.substring(11, 19)}
              </span>
            </div>
          </div>

          {/* 1. What Happened */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-bold text-[#1677C8] uppercase tracking-wider flex items-center gap-1.5">
              <span>1. What Happened</span>
            </h3>
            <div className="p-3.5 rounded-xl bg-[#F8FAFC] border border-[#DDE3EA] text-[#252B33] leading-relaxed">
              {alert.what_happened}
            </div>
          </div>

          {/* 2. Why Correlated */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-bold text-[#1677C8] uppercase tracking-wider flex items-center gap-1.5">
              <span>2. Why Events Were Correlated</span>
            </h3>
            <div className="p-3.5 rounded-xl bg-[#F8FAFC] border border-[#DDE3EA] text-[#252B33] leading-relaxed">
              {alert.why_correlated}
            </div>
          </div>

          {/* 3. What Remains Uncertain (Epistemic Modesty) */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-bold text-[#DD6B20] uppercase tracking-wider flex items-center gap-1.5">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>3. What Remains Uncertain (False Positive Considerations)</span>
            </h3>
            <div className="p-3.5 rounded-xl bg-[#FFFAF0] border border-[#FEEBC8] text-[#7B341E] leading-relaxed">
              {alert.what_remains_uncertain}
            </div>
          </div>

          {/* 4. Supporting Evidence Telemetry */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-[#6B46C1] uppercase tracking-wider">
                4. Supporting Telemetry Evidence ({alert.supporting_events?.length || alert.supporting_event_ids?.length || 0} Events)
              </h3>
              <span className="text-[11px] text-[#657180] font-mono">Click event to view in Evidence Inspector</span>
            </div>

            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {alert.supporting_events ? (
                alert.supporting_events.map((ev) => (
                  <div
                    key={ev.id}
                    onClick={() => onInspectEvent(ev)}
                    className="p-2.5 rounded-lg bg-[#F8FAFC] hover:bg-[#F1F5F9] border border-[#DDE3EA] hover:border-[#1677C8]/40 cursor-pointer transition flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-[#1677C8] font-semibold">{ev.timestamp.substring(11, 19)}</span>
                      <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold uppercase ${
                        ev.category === 'AUTHENTICATION' ? 'bg-[#EAF3FB] text-[#1677C8]' :
                        ev.category === 'NETWORK' ? 'bg-purple-50 text-[#6B46C1]' : 'bg-[#FEEBC8] text-[#DD6B20]'
                      }`}>
                        {ev.category}
                      </span>
                      <span className="font-mono text-[#252B33]">{ev.event_type}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[#657180] font-mono text-[11px]">
                        {ev.host} {ev.dest_host ? `-> ${ev.dest_host}` : ''}
                      </span>
                      <span className={`text-[10px] font-bold ${ev.action.includes('fail') ? 'text-[#C53030]' : 'text-[#16A34A]'}`}>
                        {ev.action}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-[#657180] text-xs py-2">
                  Event IDs: {alert.supporting_event_ids?.join(', ')}
                </div>
              )}
            </div>
          </div>

          {/* 5. MITRE ATT&CK Context */}
          {alert.mitre_tactics && alert.mitre_tactics.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-bold text-[#16A34A] uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" />
                <span>5. MITRE ATT&CK Technique Context</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {alert.mitre_tactics.map((m) => (
                  <div key={m.id} className="p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA]">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-[#1677C8] font-bold">{m.id} - {m.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#EAF3FB] text-[#1677C8] border border-[#BFDBFE]">
                        {m.tactic}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#475569] leading-snug">{m.description}</p>
                    {m.benign_explanations && (
                      <div className="mt-2 text-[10px] text-[#657180] pt-1.5 border-t border-[#DDE3EA]">
                        <span className="text-[#252B33] font-semibold">Benign Alternative:</span> {m.benign_explanations[0]}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 6. Recommended Analyst Actions Checklist */}
          {alert.recommended_actions && alert.recommended_actions.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-bold text-[#1677C8] uppercase tracking-wider">
                6. Recommended Analyst Investigation Checklist
              </h3>
              <div className="space-y-1.5 bg-[#F8FAFC] p-3 rounded-xl border border-[#DDE3EA]">
                {alert.recommended_actions.map((act, idx) => (
                  <div 
                    key={idx} 
                    onClick={() => toggleCheck(idx)}
                    className="flex items-start gap-2.5 cursor-pointer text-[#475569] hover:text-[#252B33] transition"
                  >
                    <div className="mt-0.5 text-[#1677C8]">
                      {checklist[idx] ? <CheckSquare className="w-4 h-4 text-[#16A34A]" /> : <Square className="w-4 h-4" />}
                    </div>
                    <span className={checklist[idx] ? 'line-through text-[#94A3B8]' : ''}>
                      {act}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer Quick Actions */}
        <div className="p-4 border-t border-[#DDE3EA] bg-white flex flex-wrap items-center justify-between gap-3 sticky bottom-0">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                onCreateCase(alert);
                onClose();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white transition shadow-sm"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              <span>Create Investigation Case</span>
            </button>

            <button
              onClick={() => {
                onOpenPlaybooks();
                onClose();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#6B46C1] border border-[#DDE3EA] transition shadow-subtle"
            >
              <Activity className="w-3.5 h-3.5 text-[#6B46C1]" />
              <span>Simulated Playbook</span>
            </button>

            <button
              onClick={() => {
                onNavigateTraceback(alert);
                onClose();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#252B33] border border-[#DDE3EA] transition shadow-subtle"
            >
              <Network className="w-3.5 h-3.5 text-[#1677C8]" />
              <span>Traceback Graph</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownloadPdf(alert.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#F0F3F6] hover:bg-[#E2E8F0] text-[#16A34A] border border-[#DDE3EA] transition shadow-subtle"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>Download PDF Dossier</span>
            </button>

            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-md text-xs font-medium text-[#657180] hover:text-[#252B33] bg-[#F0F3F6] hover:bg-[#E2E8F0] transition shadow-subtle"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
