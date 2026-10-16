import React, { useState, useEffect } from 'react';
import { 
  FolderKanban, Plus, Clock, User, ShieldAlert, 
  MessageSquare, History, CheckCircle2, ChevronRight, 
  Save, AlertTriangle, Send 
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function CaseManagement({ cases, onRefreshCases, alerts, onSelectAlert }) {
  const [activeCaseId, setActiveCaseId] = useState(cases?.[0]?.id || '');
  const [activeCaseDetail, setActiveCaseDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [newNoteAuthor, setNewNoteAuthor] = useState('SOC Tier 2 Analyst');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);

  // New Case Form State
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState('High');
  const [newCaseSummary, setNewCaseSummary] = useState('');
  const [selectedAlertIds, setSelectedAlertIds] = useState([]);

  // Fetch detailed case data
  const loadCaseDetail = async (id) => {
    if (!id) return;
    setLoading(true);
    try {
      const data = await apiClient.getCaseById(id);
      setActiveCaseDetail(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeCaseId) {
      loadCaseDetail(activeCaseId);
    } else if (cases && cases.length > 0) {
      setActiveCaseId(cases[0].id);
      loadCaseDetail(cases[0].id);
    }
  }, [activeCaseId, cases]);

  // Handle status update
  const handleStatusChange = async (newStatus) => {
    if (!activeCaseId) return;
    try {
      await apiClient.updateCase(activeCaseId, { status: newStatus });
      await loadCaseDetail(activeCaseId);
      if (onRefreshCases) onRefreshCases();
    } catch (err) {
      alert('Failed to update case status: ' + err.message);
    }
  };

  // Handle adding note
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNoteContent.trim() || !activeCaseId) return;
    try {
      await apiClient.addCaseNote(activeCaseId, {
        author: newNoteAuthor,
        content: newNoteContent
      });
      setNewNoteContent('');
      await loadCaseDetail(activeCaseId);
    } catch (err) {
      alert('Failed to add note: ' + err.message);
    }
  };

  // Handle creating new case
  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;
    try {
      const res = await apiClient.createCase({
        title: newCaseTitle,
        severity: newCaseSeverity,
        summary: newCaseSummary,
        assigned_to: newNoteAuthor,
        alert_ids: selectedAlertIds
      });
      setShowNewCaseModal(false);
      setNewCaseTitle('');
      setNewCaseSummary('');
      setSelectedAlertIds([]);
      if (onRefreshCases) await onRefreshCases();
      setActiveCaseId(res.case_id);
    } catch (err) {
      alert('Failed to create case: ' + err.message);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="bg-white border border-[#DDE3EA] rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-card">
        <div>
          <h2 className="text-base font-bold text-[#252B33] flex items-center gap-2">
            <FolderKanban className="w-4 h-4 text-[#1677C8]" />
            <span>SOC Investigation Case Management</span>
          </h2>
          <p className="text-xs text-[#657180] mt-0.5">
            Track forensic triage progress, collaborate on analyst notes, and maintain an immutable audit trail.
          </p>
        </div>

        <button
          onClick={() => setShowNewCaseModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white shadow-sm transition"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Main Split Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Cases List Pane */}
        <div className="bg-white border border-[#DDE3EA] rounded-xl p-3 space-y-2 shadow-card">
          <div className="px-2 py-1 text-[11px] font-mono text-[#657180] uppercase tracking-wider font-semibold">
            Active Cases ({cases?.length || 0})
          </div>

          <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
            {(!cases || cases.length === 0) ? (
              <div className="text-center py-10 text-[#657180] text-xs">
                No active investigation cases. Click "New Investigation Case" or open one from an alert.
              </div>
            ) : (
              cases.map((c) => {
                const isSelected = c.id === activeCaseId;
                return (
                  <div
                    key={c.id}
                    onClick={() => setActiveCaseId(c.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#EAF3FB] border-[#1677C8] shadow-sm'
                        : 'bg-[#F8FAFC] border-[#DDE3EA] hover:border-[#1677C8]/50'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                      <span className="text-[#1677C8] font-bold">{c.id}</span>
                      <span className={`px-1.5 py-0.5 rounded font-semibold uppercase text-[10px] ${
                        c.status === 'Resolved' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                        c.status === 'Contained' ? 'bg-purple-50 text-purple-700 border border-purple-200' :
                        'bg-blue-50 text-[#1677C8] border border-blue-200'
                      }`}>
                        {c.status}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-[#252B33] line-clamp-1">{c.title}</h4>
                    <div className="flex items-center justify-between text-[10px] text-[#657180] mt-2 font-mono">
                      <span>{c.assigned_to}</span>
                      <span>{c.notes_count || 0} notes</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Case Details Pane */}
        <div className="lg:col-span-2 bg-white border border-[#DDE3EA] rounded-xl p-5 space-y-5 shadow-card">
          {activeCaseDetail ? (
            <>
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#DDE3EA]">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-[#1677C8] font-bold">{activeCaseDetail.id}</span>
                    <span className="text-xs text-[#657180] font-mono">
                      Created: {activeCaseDetail.created_at?.substring(0, 10)}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-[#252B33] tracking-tight">
                    {activeCaseDetail.title}
                  </h3>
                </div>

                {/* Status Dropdown */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[#657180]">Status:</span>
                  <select
                    value={activeCaseDetail.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="bg-white border border-[#DDE3EA] rounded-md px-2.5 py-1 text-xs text-[#1677C8] font-semibold focus:outline-none focus:border-[#1677C8] shadow-subtle"
                  >
                    <option value="Active">Active</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Contained">Contained</option>
                    <option value="False Positive">False Positive</option>
                    <option value="Resolved">Resolved</option>
                  </select>
                </div>
              </div>

              {/* Case Summary */}
              {activeCaseDetail.summary && (
                <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] text-xs text-[#475569]">
                  <span className="text-[10px] font-mono text-[#657180] uppercase block mb-1 font-semibold">Case Scope</span>
                  <p>{activeCaseDetail.summary}</p>
                </div>
              )}

              {/* Linked Alerts */}
              <div>
                <span className="text-[11px] font-mono text-[#657180] uppercase tracking-wider block mb-2 font-semibold">
                  Linked Incident Alerts ({activeCaseDetail.linked_alerts?.length || 0})
                </span>
                <div className="space-y-1.5">
                  {activeCaseDetail.linked_alerts?.map((al) => (
                    <div 
                      key={al.id}
                      onClick={() => onSelectAlert && onSelectAlert(al)}
                      className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] hover:border-[#1677C8]/50 cursor-pointer transition flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[#1677C8] font-bold">{al.id}</span>
                        <span className="text-[#252B33] font-medium">{al.title}</span>
                      </div>
                      <span className="font-mono text-[10px] text-[#DD6B20] font-bold">
                        Risk: {al.risk_score}/100
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Notes Section */}
              <div className="space-y-3 pt-3 border-t border-[#DDE3EA]">
                <div className="flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-[#1677C8]" />
                  <h4 className="text-xs font-bold text-[#252B33] uppercase tracking-wider">
                    Analyst Investigation Notes & Timeline
                  </h4>
                </div>

                {/* Notes List */}
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {activeCaseDetail.notes?.length === 0 ? (
                    <div className="text-xs text-[#657180] italic">No notes recorded yet.</div>
                  ) : (
                    activeCaseDetail.notes?.map((n) => (
                      <div key={n.id} className="p-3 rounded-lg bg-[#F8FAFC] border border-[#DDE3EA] text-xs space-y-1">
                        <div className="flex items-center justify-between text-[10px] text-[#657180] font-mono">
                          <span className="text-[#1677C8] font-semibold">{n.author}</span>
                          <span>{n.created_at?.substring(11, 19)}</span>
                        </div>
                        <p className="text-[#252B33] leading-relaxed">{n.content}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="space-y-2 pt-2">
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      placeholder="Analyst Name"
                      value={newNoteAuthor}
                      onChange={(e) => setNewNoteAuthor(e.target.value)}
                      className="bg-white border border-[#DDE3EA] rounded-md px-2.5 py-1 text-xs text-[#252B33] w-44 shadow-subtle"
                    />
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Add investigation observation or verification note..."
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                      className="flex-1 bg-white border border-[#DDE3EA] rounded-md px-3 py-1.5 text-xs text-[#252B33] placeholder-[#94A3B8] focus:outline-none focus:border-[#1677C8] shadow-subtle"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 rounded-md text-xs font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white shadow-sm transition flex items-center gap-1"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Post</span>
                    </button>
                  </div>
                </form>
              </div>

              {/* Audit Trail Section */}
              <div className="space-y-2 pt-3 border-t border-[#DDE3EA]">
                <div className="flex items-center gap-2">
                  <History className="w-4 h-4 text-[#6B46C1]" />
                  <h4 className="text-xs font-bold text-[#252B33] uppercase tracking-wider">
                    Immutable Case Audit Trail
                  </h4>
                </div>

                <div className="space-y-1.5 max-h-36 overflow-y-auto font-mono text-[11px]">
                  {activeCaseDetail.audit_logs?.map((au) => (
                    <div key={au.id} className="p-2 rounded bg-[#F8FAFC] border border-[#DDE3EA] flex items-center justify-between text-[#657180]">
                      <div>
                        <span className="text-[#1677C8] font-semibold">{au.action}</span>: {au.details}
                      </div>
                      <span className="text-[10px] text-[#94A3B8] shrink-0 ml-2">
                        {au.performed_by} • {au.timestamp?.substring(11, 19)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-20 text-center text-[#657180] text-xs">
              Select an investigation case to view details and audit logs.
            </div>
          )}
        </div>
      </div>

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white border border-[#DDE3EA] rounded-2xl w-full max-w-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-[#252B33]">Create New Investigation Case</h3>
            
            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <div>
                <label className="block text-[#657180] mb-1 font-medium">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Host WORKSTATION-04 Compromise"
                  value={newCaseTitle}
                  onChange={(e) => setNewCaseTitle(e.target.value)}
                  className="w-full bg-white border border-[#DDE3EA] rounded-md p-2 text-[#252B33] shadow-subtle focus:border-[#1677C8]"
                />
              </div>

              <div>
                <label className="block text-[#657180] mb-1 font-medium">Severity</label>
                <select
                  value={newCaseSeverity}
                  onChange={(e) => setNewCaseSeverity(e.target.value)}
                  className="w-full bg-white border border-[#DDE3EA] rounded-md p-2 text-[#252B33] shadow-subtle focus:border-[#1677C8]"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-[#657180] mb-1 font-medium">Investigation Scope / Summary</label>
                <textarea
                  rows="3"
                  placeholder="Describe initial hypotheses, scope of triage, and affected assets..."
                  value={newCaseSummary}
                  onChange={(e) => setNewCaseSummary(e.target.value)}
                  className="w-full bg-white border border-[#DDE3EA] rounded-md p-2 text-[#252B33] shadow-subtle focus:border-[#1677C8]"
                />
              </div>

              {alerts && alerts.length > 0 && (
                <div>
                  <label className="block text-[#657180] mb-1 font-medium">Link Alerts (Optional)</label>
                  <div className="max-h-28 overflow-y-auto space-y-1 bg-[#F8FAFC] p-2 rounded-md border border-[#DDE3EA]">
                    {alerts.map(a => (
                      <label key={a.id} className="flex items-center gap-2 cursor-pointer text-[#475569]">
                        <input
                          type="checkbox"
                          checked={selectedAlertIds.includes(a.id)}
                          onChange={(e) => {
                            if (e.target.checked) setSelectedAlertIds([...selectedAlertIds, a.id]);
                            else setSelectedAlertIds(selectedAlertIds.filter(id => id !== a.id));
                          }}
                        />
                        <span className="font-mono text-[10px] text-[#1677C8] font-semibold">{a.id}</span>
                        <span className="truncate">{a.title}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#DDE3EA]">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="px-3 py-1.5 rounded-md text-[#657180] hover:text-[#252B33]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-md font-semibold bg-[#1677C8] hover:bg-[#1366AC] text-white shadow-sm"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
