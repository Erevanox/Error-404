import React from 'react';
import logoImg from '../assets/logo.png';
import { 
  Upload, RefreshCw, Zap, FileDown, 
  Trash2, Database, AlertCircle, CheckCircle2 
} from 'lucide-react';

export default function Navbar({ 
  onOpenUpload, 
  onLoadCanonical, 
  onResetDemo, 
  onClearData,
  onOpenExport,
  loading,
  hasActiveData,
  eventCount = 0
}) {
  return (
    <header className="bg-white border-b border-[#E2E8F0] sticky top-0 z-40 px-4 lg:px-6 py-2.5 shadow-subtle text-[#0F172A]">
      <div className="flex items-center justify-between gap-4">
        {/* Brand & Wordmark */}
        <div className="flex items-center gap-2.5">
          <img 
            src={logoImg} 
            alt="TraceX Logo" 
            className="h-8 w-auto max-h-8 object-contain shrink-0 select-none"
          />
          <div className="flex items-center gap-2">
            <span className="text-base font-bold tracking-tight text-[#0F172A]">
              TraceX
            </span>
            <span className="text-[10px] font-mono tracking-wider px-1.5 py-0.5 rounded bg-[#F1F5F9] text-[#64748B] border border-[#E2E8F0] uppercase font-semibold">
              Cybersecurity Platform
            </span>
          </div>
        </div>

        {/* Current Investigation Status */}
        <div className="hidden md:flex items-center gap-2.5 px-3 py-1 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono">
          {hasActiveData ? (
            <>
              <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
              <span className="text-[#0F172A] text-[11px] font-semibold">
                Active Investigation ({eventCount} records)
              </span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-[#94A3B8]" />
              <span className="text-[#64748B] text-[11px]">
                Ready — Awaiting Log File
              </span>
            </>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Upload Log File Button */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-subtle transition"
            title="Upload CSV or JSON log file"
          >
            <Upload className="w-3.5 h-3.5 text-white" />
            <span>Upload Log File</span>
          </button>

          {/* Export Report Button */}
          <button
            onClick={onOpenExport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-[#F8FAFC] text-[#0F172A] border border-[#E2E8F0] transition shadow-subtle"
            title="Export Investigation Report (PDF / CSV)"
          >
            <FileDown className="w-3.5 h-3.5 text-[#64748B]" />
            <span className="hidden sm:inline">Export Report</span>
          </button>

          {/* Explicit Load Demo Data button */}
          <button
            onClick={onLoadCanonical}
            disabled={loading}
            className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-[#F8FAFC] text-[#D97706] border border-[#E2E8F0] transition shadow-subtle"
            title="Explicitly load demo attack scenario"
          >
            <Zap className="w-3.5 h-3.5 text-[#D97706]" />
            <span>Load Demo Data</span>
          </button>

          {/* Clear Data Button (when active data exists) */}
          {hasActiveData && (
            <button
              onClick={onClearData}
              disabled={loading}
              className="p-1.5 rounded-lg text-[#64748B] hover:text-[#DC2626] bg-white hover:bg-[#FEF2F2] border border-[#E2E8F0] hover:border-[#FCA5A5] transition shadow-subtle"
              title="Clear active investigation data"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

