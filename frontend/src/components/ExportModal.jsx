import React, { useState, useMemo } from 'react';
import { 
  X, FileDown, FileText, FileSpreadsheet, Shield, 
  CheckCircle2, Download, AlertTriangle, AlertCircle,
  Calendar, Clock, Globe, Code2, Eye
} from 'lucide-react';
import { apiClient } from '../api/client';
import jsPDF from 'jspdf';
import 'jspdf-autotable';

// Helper to format sample date for live preview
function formatTimestampPreview(dateObj, dateFormat, timeFormat, timezone) {
  const pad = (n) => String(n).padStart(2, '0');
  const year = dateObj.getUTCFullYear();
  const month = pad(dateObj.getUTCMonth() + 1);
  const day = pad(dateObj.getUTCDate());

  let datePart = `${year}-${month}-${day}`;
  if (dateFormat === 'DD-MM-YYYY') datePart = `${day}-${month}-${year}`;
  else if (dateFormat === 'MM-DD-YYYY') datePart = `${month}-${day}-${year}`;
  else if (dateFormat === 'DD/MM/YYYY') datePart = `${day}/${month}/${year}`;

  const hours24 = dateObj.getUTCHours();
  const minutes = pad(dateObj.getUTCMinutes());
  const seconds = pad(dateObj.getUTCSeconds());

  let timePart = `${pad(hours24)}:${minutes}:${seconds}`;
  if (timeFormat === '12h') {
    const period = hours24 >= 12 ? 'PM' : 'AM';
    const hours12 = hours24 % 12 || 12;
    timePart = `${pad(hours12)}:${minutes}:${seconds} ${period}`;
  }

  return `${datePart} ${timePart} ${timezone}`;
}

export default function ExportModal({ isOpen, onClose, alerts = [], events = [], stats = null }) {
  if (!isOpen) return null;

  const hasData = (events && events.length > 0) || (alerts && alerts.length > 0);
  const [selectedAlertId, setSelectedAlertId] = useState(alerts?.[0]?.id || '');
  const [downloading, setDownloading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  // Format preferences (Phase 5 requirement)
  const [dateFormat, setDateFormat] = useState('YYYY-MM-DD');
  const [timeFormat, setTimeFormat] = useState('24h');
  const [timezonePref, setTimezonePref] = useState('UTC');

  // Sample timestamp for live preview
  const livePreview = useMemo(() => {
    const sampleDate = events?.[0]?.timestamp ? new Date(events[0].timestamp) : new Date();
    return formatTimestampPreview(sampleDate, dateFormat, timeFormat, timezonePref);
  }, [events, dateFormat, timeFormat, timezonePref]);

  // Handle Backend PDF Download with Client-Side Fallback
  const handleDownloadPdf = async () => {
    setDownloading(true);
    setStatusMsg('Compiling TraceX investigation dossier...');

    try {
      const pdfUrl = apiClient.getPdfUrl(selectedAlertId, dateFormat, timeFormat, timezonePref);
      const response = await fetch(pdfUrl);
      if (!response.ok) throw new Error('Backend PDF endpoint error');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = selectedAlertId 
        ? `TraceX_Report_${selectedAlertId}.pdf` 
        : `TraceX_Cybersecurity_Investigation_Report.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setStatusMsg(`TraceX PDF report downloaded successfully (Format: ${dateFormat} ${timeFormat}).`);
    } catch (err) {
      console.warn('Backend PDF generation fallback to client-side jsPDF:', err);
      generateClientSidePdf();
    } finally {
      setDownloading(false);
    }
  };

  // Client-Side PDF Generation Fallback using jsPDF
  const generateClientSidePdf = () => {
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
    doc.text('CYBERSECURITY INCIDENT INVESTIGATION DOSSIER', 14, 16);

    const nowFormatted = formatTimestampPreview(new Date(), dateFormat, timeFormat, timezonePref);
    doc.setFontSize(7);
    doc.setTextColor(203, 213, 225);
    doc.text(`GENERATED: ${nowFormatted}`, 200, 11, { align: 'right' });
    doc.setTextColor(251, 191, 36);
    doc.text('TLP:AMBER // CONFIDENTIAL', 200, 16, { align: 'right' });

    if (!hasData) {
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.text('INVESTIGATION STATUS: CLEAN / ZERO TELEMETRY INGESTED', 14, 32);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text('Total processed records: 0  |  Detection alerts: 0  |  Correlated alerts: 0', 14, 38);
      doc.text('No log telemetry files have been uploaded to the TraceX investigation engine yet.', 14, 44);
      doc.save('TraceX_Empty_Investigation_Report.pdf');
      setStatusMsg('Empty investigation report generated.');
      return;
    }

    const alert = alerts?.find(a => a.id === selectedAlertId) || alerts?.[0];

    let y = 28;
    // Overview Box
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(14, y, 187.9, 24, 1.5, 1.5, 'FD');

    doc.setTextColor(15, 23, 42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.text(`INCIDENT ID: ${alert?.id || 'ALT-GENERAL'}`, 18, y + 6);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(`TITLE: ${alert?.title || 'Correlated Security Threat'}`, 18, y + 11);
    doc.text(`SEVERITY: ${alert?.severity || 'HIGH'}  |  CONFIDENCE: ${alert?.confidence_score || '85'}%  |  ATTACK STAGE: ${alert?.attack_stage || 'Active'}`, 18, y + 16);
    doc.text(`OBSERVED WINDOW: ${alert?.first_seen ? formatTimestampPreview(new Date(alert.first_seen), dateFormat, timeFormat, timezonePref) : 'N/A'} - ${alert?.last_seen ? formatTimestampPreview(new Date(alert.last_seen), dateFormat, timeFormat, timezonePref) : 'N/A'}`, 18, y + 21);

    y += 30;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.text('CHRONOLOGICAL FORENSIC TIMELINE & SUPPORTING EVIDENCE', 14, y);
    y += 4;

    const tableEvents = (alert?.supporting_events || events || []).slice(0, 15);
    const tableRows = tableEvents.map(e => [
      e.timestamp ? formatTimestampPreview(new Date(e.timestamp), dateFormat, timeFormat, timezonePref) : 'N/A',
      e.category || 'GENERIC',
      e.user || '-',
      e.host || e.source_ip || '-',
      e.action || e.status || '-',
      e.event_type || '-'
    ]);

    doc.autoTable({
      startY: y,
      head: [['Timestamp', 'Category', 'User', 'Source', 'Action', 'Event Type']],
      body: tableRows,
      theme: 'grid',
      styles: { fontSize: 7, cellPadding: 1.5, textColor: [30, 41, 59] },
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
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

    doc.save(`TraceX_Report_${alert?.id || 'General'}.pdf`);
    setStatusMsg(`PDF generated and downloaded via browser client (Format: ${dateFormat} ${timeFormat}).`);
  };

  // Handle CSV Download
  const handleDownloadCsv = () => {
    if (!hasData) {
      setStatusMsg('No evidence records to export. Ingest a log file first.');
      return;
    }
    const csvUrl = apiClient.getCsvUrl(dateFormat, timeFormat, timezonePref);
    window.location.href = csvUrl;
    setStatusMsg(`CSV evidence export initiated with ${dateFormat} ${timeFormat} formatting.`);
  };

  // Handle JSON Download
  const handleDownloadJson = () => {
    if (!hasData) {
      setStatusMsg('No evidence records to export. Ingest a log file first.');
      return;
    }
    const jsonUrl = apiClient.getJsonUrl(dateFormat, timeFormat, timezonePref);
    window.location.href = jsonUrl;
    setStatusMsg(`JSON evidence export initiated with ${dateFormat} ${timeFormat} formatting.`);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white border border-[#E2E8F0] rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col text-[#0F172A] max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-[#E2E8F0] flex items-center justify-between bg-[#F8FAFC]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] text-[#059669]">
              <FileDown className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#0F172A] tracking-tight">
                Export Forensics &amp; Reports
              </h2>
              <p className="text-xs text-[#64748B]">
                Configure export format, date/time preferences, and download forensic dossiers.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0F172A] bg-white hover:bg-[#F1F5F9] border border-[#E2E8F0] transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 text-xs overflow-y-auto">
          {!hasData && (
            <div className="p-3 rounded-lg bg-[#FFFBEB] border border-[#FEF3C7] text-[#B45309] flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">No Investigation Data Loaded</span>
                <span className="text-[11px] text-[#64748B]">
                  Exporting now will produce an honest empty report indicating zero records processed.
                </span>
              </div>
            </div>
          )}

          {/* Date & Time Preferences Card (Phase 5 Requirement) */}
          <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#CBD5E1] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                <Calendar className="w-4 h-4 text-[#0284C7]" />
                <span>Export Timestamp Formatting Preferences</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#E0F2FE] text-[#0369A1] font-semibold">
                Formatting Engine
              </span>
            </div>
            <p className="text-[11px] text-[#64748B]">
              Choose how event timestamps are displayed across exported CSV, JSON, and PDF documents. Underlying UTC data integrity remains preserved.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              {/* Date Format */}
              <div>
                <label className="block text-[11px] text-[#475569] mb-1 font-semibold">
                  Date Format
                </label>
                <select
                  value={dateFormat}
                  onChange={(e) => setDateFormat(e.target.value)}
                  className="w-full bg-white border border-[#CBD5E1] rounded-lg p-2 text-[#0F172A] font-mono text-xs focus:outline-none focus:border-[#0284C7]"
                >
                  <option value="YYYY-MM-DD">YYYY-MM-DD (ISO 8601)</option>
                  <option value="DD-MM-YYYY">DD-MM-YYYY (European)</option>
                  <option value="MM-DD-YYYY">MM-DD-YYYY (US Standard)</option>
                  <option value="DD/MM/YYYY">DD/MM/YYYY (Slash)</option>
                </select>
              </div>

              {/* Time Format */}
              <div>
                <label className="block text-[11px] text-[#475569] mb-1 font-semibold">
                  Time Format
                </label>
                <select
                  value={timeFormat}
                  onChange={(e) => setTimeFormat(e.target.value)}
                  className="w-full bg-white border border-[#CBD5E1] rounded-lg p-2 text-[#0F172A] font-mono text-xs focus:outline-none focus:border-[#0284C7]"
                >
                  <option value="24h">24-Hour (HH:mm:ss)</option>
                  <option value="12h">12-Hour (hh:mm:ss AM/PM)</option>
                </select>
              </div>

              {/* Timezone */}
              <div>
                <label className="block text-[11px] text-[#475569] mb-1 font-semibold">
                  Timezone Standard
                </label>
                <select
                  value={timezonePref}
                  onChange={(e) => setTimezonePref(e.target.value)}
                  className="w-full bg-white border border-[#CBD5E1] rounded-lg p-2 text-[#0F172A] font-mono text-xs focus:outline-none focus:border-[#0284C7]"
                >
                  <option value="UTC">UTC (Coordinated Universal)</option>
                </select>
              </div>
            </div>

            {/* Live Preview Box */}
            <div className="p-2.5 rounded-lg bg-white border border-[#E2E8F0] flex items-center justify-between text-[11px]">
              <div className="flex items-center gap-1.5 text-[#64748B]">
                <Eye className="w-3.5 h-3.5 text-[#0284C7]" />
                <span className="font-medium">Live Timestamp Preview:</span>
              </div>
              <span className="font-mono font-bold text-[#0F172A] bg-[#F1F5F9] px-2 py-0.5 rounded border border-[#CBD5E1]">
                {livePreview}
              </span>
            </div>
          </div>

          {/* Export Options Grid */}
          <div className="grid grid-cols-1 gap-3">
            {/* 1. PDF Investigation Dossier */}
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                    <FileText className="w-4 h-4 text-[#10B981]" />
                    <span>TraceX Investigation Dossier (PDF)</span>
                  </div>
                  <p className="text-[11px] text-[#64748B] mt-0.5">
                    Multi-section forensic report with executive metrics, entity attribution, timeline, and MITRE mapping.
                  </p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0] font-semibold">
                  PDF
                </span>
              </div>

              {alerts && alerts.length > 0 && (
                <div>
                  <label className="block text-[11px] text-[#64748B] mb-1 font-medium">Select Target Incident Scope:</label>
                  <select
                    value={selectedAlertId}
                    onChange={(e) => setSelectedAlertId(e.target.value)}
                    className="w-full bg-white border border-[#E2E8F0] rounded-lg p-2 text-[#0F172A] font-mono text-xs focus:outline-none focus:border-[#10B981]"
                  >
                    <option value="">General SOC Investigation Dossier (All Active Records)</option>
                    {alerts.map(a => (
                      <option key={a.id} value={a.id}>
                        {a.id} ({a.severity}) — {a.title.substring(0, 42)}...
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <button
                onClick={handleDownloadPdf}
                disabled={downloading}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-subtle transition disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                <span>{downloading ? 'Compiling Dossier...' : 'Download PDF Investigation Dossier'}</span>
              </button>
            </div>

            {/* 2. CSV Evidence Dump */}
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                    <FileSpreadsheet className="w-4 h-4 text-[#D97706]" />
                    <span>CSV Raw Evidence Export</span>
                  </div>
                  <p className="text-[11px] text-[#64748B] mt-0.5">
                    Export all normalized event fields and original raw log strings with preferred date/time formatting.
                  </p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FFFBEB] text-[#D97706] border border-[#FEF3C7] font-semibold">
                  CSV
                </span>
              </div>

              <button
                onClick={handleDownloadCsv}
                disabled={!hasData}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg font-semibold bg-white hover:bg-[#F1F5F9] text-[#0F172A] border border-[#E2E8F0] transition disabled:opacity-50 shadow-subtle"
              >
                <Download className="w-4 h-4 text-[#D97706]" />
                <span>Export Telemetry Records (.CSV)</span>
              </button>
            </div>

            {/* 3. JSON Structured Forensics Export */}
            <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                    <Code2 className="w-4 h-4 text-[#8B5CF6]" />
                    <span>JSON Forensic Telemetry Package</span>
                  </div>
                  <p className="text-[11px] text-[#64748B] mt-0.5">
                    Machine-readable JSON export with correlated incidents, event list, metadata, and formatted timestamps.
                  </p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#F5F3FF] text-[#7C3AED] border border-[#DDD6FE] font-semibold">
                  JSON
                </span>
              </div>

              <button
                onClick={handleDownloadJson}
                disabled={!hasData}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg font-semibold bg-white hover:bg-[#F1F5F9] text-[#0F172A] border border-[#E2E8F0] transition disabled:opacity-50 shadow-subtle"
              >
                <Download className="w-4 h-4 text-[#7C3AED]" />
                <span>Export Machine-Readable Telemetry (.JSON)</span>
              </button>
            </div>
          </div>

          {statusMsg && (
            <div className="p-2.5 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] text-[#059669] text-center font-mono text-[11px]">
              {statusMsg}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-[#E2E8F0] bg-[#F8FAFC] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold text-[#64748B] hover:text-[#0F172A] bg-white hover:bg-[#F1F5F9] border border-[#E2E8F0] transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
