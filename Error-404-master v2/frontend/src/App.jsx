import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import AlertsList from './components/AlertsList';
import IncidentScatterPlot from './components/IncidentScatterPlot';
import EventTimeline from './components/EventTimeline';
import IncidentActivityTrend from './components/IncidentActivityTrend';
import TracebackGraph from './components/TracebackGraph';
import EvidenceInspector from './components/EvidenceInspector';
import MitreMatrix from './components/MitreMatrix';
import CaseManagement from './components/CaseManagement';
import AlertDetailModal from './components/AlertDetailModal';
import LogUploadModal from './components/LogUploadModal';
import PlaybooksModal from './components/PlaybooksModal';
import ExportModal from './components/ExportModal';
import SocSimulator from './components/SocSimulator';
import { apiClient } from './api/client';
import { Shield, AlertCircle, RefreshCw } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Core Data State
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [cases, setCases] = useState([]);

  // Active Modals & Selections
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [investigatingAlert, setInvestigatingAlert] = useState(null);
  const [returnAlertContext, setReturnAlertContext] = useState(null);
  const [inspectingEvent, setInspectingEvent] = useState(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isPlaybooksOpen, setIsPlaybooksOpen] = useState(false);
  const [isExportOpen, setIsExportOpen] = useState(false);

  // Fetch all core SOC telemetry
  const refreshAllData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, eventsRes, alertsRes, casesRes] = await Promise.all([
        apiClient.getStats(),
        apiClient.getEvents({ limit: 1000 }),
        apiClient.getAlerts(),
        apiClient.getCases(),
      ]);
      setStats(statsRes);
      setEvents(eventsRes.events || []);
      setAlerts(alertsRes.alerts || []);
      setCases(casesRes.cases || []);

      // If an alert was previously selected, refresh its details
      if (selectedAlert) {
        const refreshed = alertsRes.alerts?.find(a => a.id === selectedAlert.id);
        if (refreshed) {
          const detail = await apiClient.getAlertById(refreshed.id);
          setSelectedAlert(detail);
        }
      }
    } catch (err) {
      console.error('Data fetch error:', err);
      setError(err.message || 'Failed to communicate with SOC backend API');
    } finally {
      setLoading(false);
    }
  }, [selectedAlert]);

  useEffect(() => {
    refreshAllData();
  }, []);

  // Handlers
  const handleInspectEvent = (ev, context = null) => {
    setInspectingEvent(ev);
    if (context?.returnToAlert) {
      setReturnAlertContext(context.returnToAlert);
    } else {
      setReturnAlertContext(null);
    }
    setActiveTab('inspector');
    setSelectedAlert(null); // Close modal if open
  };

  const handleSelectAlert = async (alert) => {
    try {
      const detail = await apiClient.getAlertById(alert.id);
      setSelectedAlert(detail);
    } catch {
      setSelectedAlert(alert);
    }
  };

  const handleResetDemo = async () => {
    setLoading(true);
    try {
      await apiClient.resetDemo();
      await refreshAllData();
    } catch (err) {
      alert('Reset failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClearData = async () => {
    setLoading(true);
    try {
      await apiClient.clearData();
      await refreshAllData();
      setActiveTab('dashboard');
    } catch (err) {
      alert('Clear failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadCanonical = async () => {
    setLoading(true);
    try {
      await apiClient.loadSample('canonical');
      await refreshAllData();
      setActiveTab('dashboard');
    } catch (err) {
      alert('Load failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCaseFromAlert = async (alert) => {
    try {
      const res = await apiClient.createCase({
        title: `Investigation: ${alert.title}`,
        severity: alert.severity,
        summary: alert.what_happened,
        assigned_to: 'SOC Tier 2 Analyst',
        alert_ids: [alert.id]
      });
      await refreshAllData();
      setActiveTab('cases');
    } catch (err) {
      alert('Failed to create case: ' + err.message);
    }
  };

  const handleDownloadPdf = (alertId) => {
    window.location.href = apiClient.getPdfUrl(alertId);
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-[#0F172A] flex flex-col font-sans selection:bg-[#10B981] selection:text-white">
      {/* Top SOC Navbar */}
      <Navbar
        onOpenUpload={() => setIsUploadOpen(true)}
        onLoadCanonical={handleLoadCanonical}
        onResetDemo={handleResetDemo}
        onClearData={handleClearData}
        onOpenPlaybooks={() => setIsPlaybooksOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        loading={loading}
        hasActiveData={(events?.length || 0) > 0}
        eventCount={events?.length || 0}
      />

      {/* Main Body with Sidebar & Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onTabChange={(tab) => {
            if (tab === 'playbooks') {
              setIsPlaybooksOpen(true);
            } else {
              setActiveTab(tab);
            }
          }}
          alertCount={alerts?.length || 0}
          caseCount={cases?.length || 0}
          onOpenExport={() => setIsExportOpen(true)}
        />

        {/* Content Viewport */}
        <main className="flex-1 p-4 lg:p-6 overflow-y-auto max-h-[calc(100vh-53px)] bg-[#F8FAFC]">
          {error && (
            <div className="mb-4 p-3.5 rounded-xl bg-[#FEF2F2] border border-[#FECACA] text-[#DC2626] text-xs flex items-center justify-between shadow-subtle">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-[#DC2626] shrink-0" />
                <span>Backend API Warning: {error}. Ensure FastAPI is running on port 8000.</span>
              </div>
              <button
                onClick={refreshAllData}
                className="px-2.5 py-1 rounded bg-[#DC2626] hover:bg-[#B91C1C] text-white font-mono text-[11px] transition shadow-subtle"
              >
                Retry Connection
              </button>
            </div>
          )}

          {/* Active View Switcher */}
          {activeTab === 'dashboard' && (
            <Dashboard
              stats={stats}
              events={events}
              alerts={alerts}
              onSelectAlert={handleSelectAlert}
              onInspectEvent={handleInspectEvent}
              onNavigateTab={setActiveTab}
              onOpenUpload={() => setIsUploadOpen(true)}
              onLoadScenario={async (scenario) => {
                await apiClient.loadSample(scenario);
                await refreshAllData();
              }}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsList
              alerts={alerts}
              events={events}
              investigatingAlert={investigatingAlert}
              onInvestigateAlert={setInvestigatingAlert}
              onSelectAlert={handleSelectAlert}
              onInspectEvidence={(ev, alert) => {
                handleInspectEvent(ev, { returnToAlert: alert });
              }}
              onNavigateTraceback={(alert) => {
                setSelectedAlert(alert);
                setActiveTab('traceback');
              }}
              onNavigateGraph={(alert) => {
                setSelectedAlert(alert);
                setActiveTab('trend');
              }}
              onCreateCase={handleCreateCaseFromAlert}
              onDownloadPdf={handleDownloadPdf}
            />
          )}

          {activeTab === 'trend' && (
            <IncidentActivityTrend
              alerts={alerts}
              events={events}
              selectedAlert={selectedAlert}
              onSelectAlert={handleSelectAlert}
              onInspectEvent={handleInspectEvent}
              onNavigateTab={setActiveTab}
              onDownloadPdf={handleDownloadPdf}
            />
          )}

          {activeTab === 'scatter' && (
            <IncidentScatterPlot
              events={events}
              onInspectEvent={handleInspectEvent}
            />
          )}

          {activeTab === 'timeline' && (
            <EventTimeline
              events={events}
              alerts={alerts}
              selectedAlert={selectedAlert}
              onInspectEvent={handleInspectEvent}
            />
          )}

          {activeTab === 'traceback' && (
            <TracebackGraph
              alerts={alerts}
              events={events}
              selectedAlert={selectedAlert}
              onSelectAlert={handleSelectAlert}
              onInspectEvent={handleInspectEvent}
              onNavigateTab={setActiveTab}
              onOpenExport={() => setIsExportOpen(true)}
              onOpenUpload={() => setIsUploadOpen(true)}
              onLoadCanonical={handleLoadCanonical}
            />
          )}

          {activeTab === 'inspector' && (
            <EvidenceInspector
              events={events}
              initialEvent={inspectingEvent}
              returnAlertContext={returnAlertContext}
              onReturnToAlert={(alert) => {
                setInvestigatingAlert(alert);
                setActiveTab('alerts');
              }}
            />
          )}

          {activeTab === 'mitre' && (
            <MitreMatrix />
          )}

          {activeTab === 'cases' && (
            <CaseManagement
              cases={cases}
              onRefreshCases={refreshAllData}
              alerts={alerts}
              onSelectAlert={handleSelectAlert}
            />
          )}

          {activeTab === 'simulator' && (
            <SocSimulator defaultTarget={selectedAlert?.primary_user || 'm.vasquez'} />
          )}
        </main>
      </div>

      {/* Alert Detail & Explainability Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onInspectEvent={(ev) => handleInspectEvent(ev, { returnToAlert: selectedAlert })}
          onNavigateTraceback={(alert) => {
            setSelectedAlert(alert);
            setActiveTab('traceback');
          }}
          onCreateCase={handleCreateCaseFromAlert}
          onOpenPlaybooks={() => setIsPlaybooksOpen(true)}
          onDownloadPdf={handleDownloadPdf}
        />
      )}

      {/* Log Upload & Parser Modal */}
      <LogUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={refreshAllData}
        hasActiveData={(events?.length || 0) > 0}
      />

      {/* Response Playbooks Simulation Modal */}
      <PlaybooksModal
        isOpen={isPlaybooksOpen}
        onClose={() => setIsPlaybooksOpen(false)}
        defaultTarget={selectedAlert?.primary_user || 'm.vasquez'}
      />

      {/* Export Report & Evidence Modal */}
      <ExportModal
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        alerts={alerts}
        events={events}
        stats={stats}
      />
    </div>
  );
}
