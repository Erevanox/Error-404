import React, { useState } from 'react';
import { 
  X, FileDown, FileText, FileSpreadsheet, Shield, 
  CheckCircle2, Download, AlertTriangle, AlertCircle 
} from 'lucide-react';
import { apiClient } from '../api/client';
import jsPDF from 'jspdf';
import 'jspdf-autotable';

export default function ExportModal({ isOpen, onClose, alerts = [], events = [], stats = null }) {
  if (!isOpen) return null;

  const hasData = (events && events.length > 0) || (alerts && alerts.length > 0);
  const [selectedAlertId, setSelectedAlertId] = useState(alerts?.[0]?.id || '');
  const [downloading, setDownloading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  // Handle Backend PDF Download with Client-Side Fallback
  const handleDownloadPdf = async () => {
    setDownloading(true);
    setStatusMsg('Compiling TraceX investigation dossier...');

    try {
      const pdfUrl = selectedAlertId 
        ? apiClient.getPdfUrl(selectedAlertId) 
        : apiClient.getPdfUrl('');
        
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
      setStatusMsg('TraceX PDF report downloaded successfully.');
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

    const now = new Date().toUTCString();
    doc.setFontSize(7);
    doc.setTextColor(203, 213, 225);
    doc.text(`GENERATED: ${now}`, 200, 11, { align: 'right' });
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
    doc.setFontSize(9.5);
    doc.text(`Incident: ${alert ? alert.title : 'General Telemetry Audit'}`, 18, y + 6);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text(`Alert ID: ${alert?.id || 'N/A'}   |   Risk Score: ${alert?.risk_score || 0}/100   |   Severity: ${alert?.severity || 'Informational'}`, 18, y + 12);
    doc.text(`Target User: ${alert?.primary_user || 'system'}   |   Foothold Host: ${alert?.primary_host || 'N/A'}   |   Origin IP: ${alert?.primary_ip || 'N/A'}`, 18, y + 17);
    doc.text(`Time Window: ${(alert?.first_seen || 'N/A').replace('T', ' ').replace('Z', ' UTC')} to ${(alert?.last_seen || 'N/A').replace('T', ' ').replace('Z', ' UTC')}`, 18, y + 22);

    y += 30;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('1. Executive Incident Summary & Detection Rationale', 14, y);
    y += 4;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const summaryLines = doc.splitTextToSize(alert?.what_happened || 'Correlated security events identified by telemetry rules.', 185);
    doc.text(summaryLines, 14, y);
    y += (summaryLines.length * 3.8) + 2;

    const rationaleLines = doc.splitTextToSize(`Detection Rationale: ${alert?.why_correlated || 'Events correlated via heuristic rules based on entity chaining.'}`, 185);
    doc.setTextColor(13, 148, 136);
    doc.text(rationaleLines, 14, y);
    y += (rationaleLines.length * 3.8) + 4;

    // Supporting Evidence Table
    const tableRows = (alert?.supporting_events || events || []).slice(0, 14).map(e => [
      e.timestamp ? e.timestamp.substring(11, 19) : '-',
      (e.category || '-').toUpperCase(),
      e.user || '-',
      e.host || '-',
      e.action || e.status || '-',
      `${e.severity_score || 1.0}`,
      (e.event_type || '').replace('_', ' ')
    ]);

    doc.autoTable({
      startY: y,
      head: [['Time (UTC)', 'Category', 'User', 'Host', 'Action', 'Risk', 'Context']],
      body: tableRows,
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

    doc.save(`TraceX_Report_${alert?.id || 'General'}.pdf`);
    setStatusMsg('PDF generated and downloaded via browser client.');
  };

  // Handle CSV Download
  const handleDownloadCsv = () => {
    if (!hasData) {
      setStatusMsg('No evidence records to export. Ingest a log file first.');
      return;
    }
    const csvUrl = apiClient.getCsvUrl();
    window.location.href = csvUrl;
    setStatusMsg('CSV evidence export initiated.');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white border border-[#E2E8F0] rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl flex flex-col text-[#0F172A]">
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
                Generate TraceX investigation reports (PDF) and raw evidence dumps (CSV).
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
        <div className="p-5 space-y-4 text-xs">
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

          {/* PDF Report Option */}
          <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                  <FileText className="w-4 h-4 text-[#10B981]" />
                  <span>TraceX Cybersecurity Investigation Report (PDF)</span>
                </div>
                <p className="text-[11px] text-[#64748B] mt-0.5">
                  Multi-section forensic report with summary metrics, suspicious activity, timeline, and MITRE mapping.
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0] font-semibold">
                PDF
              </span>
            </div>

            {alerts && alerts.length > 0 && (
              <div>
                <label className="block text-[11px] text-[#64748B] mb-1 font-medium">Select Correlated Alert:</label>
                <select
                  value={selectedAlertId}
                  onChange={(e) => setSelectedAlertId(e.target.value)}
                  className="w-full bg-white border border-[#E2E8F0] rounded-lg p-2 text-[#0F172A] font-mono text-xs focus:outline-none focus:border-[#10B981]"
                >
                  <option value="">General Overall Investigation Dossier</option>
                  {alerts.map(a => (
                    <option key={a.id} value={a.id}>
                      {a.id} ({a.severity}) - {a.title.substring(0, 36)}...
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
              <span>{downloading ? 'Compiling Dossier...' : 'Download PDF Investigation Report'}</span>
            </button>
          </div>

          {/* CSV Evidence Export Option */}
          <div className="p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-1.5 font-bold text-[#0F172A]">
                  <FileSpreadsheet className="w-4 h-4 text-[#D97706]" />
                  <span>CSV Raw Evidence Export</span>
                </div>
                <p className="text-[11px] text-[#64748B] mt-0.5">
                  Export all normalized event fields and original raw log strings for external analysis.
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
