import React, { useState, useEffect } from 'react';
import { 
  X, Upload, FileText, CheckCircle2, AlertTriangle, 
  RefreshCw, FileSpreadsheet, PlusCircle, Info, ShieldCheck,
  Clock, Check
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function LogUploadModal({ isOpen, onClose, onUploadSuccess, hasActiveData }) {
  if (!isOpen) return null;

  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  // null = not yet chosen when hasActiveData, 'append' | 'clear' once chosen
  const [uploadMode, setUploadMode] = useState(hasActiveData ? null : 'clear');

  // Reset state when modal is closed
  useEffect(() => {
    if (!isOpen) {
      setSelectedFile(null);
      setUploadResult(null);
      setErrorMessage(null);
      setUploadMode(hasActiveData ? null : 'clear');
    }
  }, [isOpen, hasActiveData]);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelected(e.target.files[0]);
    }
  };

  const handleFileSelected = (file) => {
    setErrorMessage(null);
    setUploadResult(null);
    if (!file.name.endsWith('.json') && !file.name.endsWith('.csv')) {
      setErrorMessage('Unsupported file format. Please upload a CSV or JSON log file.');
      return;
    }
    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile || uploadMode === null) return;
    setUploading(true);
    setErrorMessage(null);
    setUploadResult(null);

    try {
      const res = await apiClient.uploadFile(selectedFile, uploadMode);
      setUploadResult(res);
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setErrorMessage(err.message || 'File upload failed. Check format.');
    } finally {
      setUploading(false);
    }
  };

  const handleResetForNewFile = () => {
    setSelectedFile(null);
    setUploadResult(null);
    setErrorMessage(null);
    setUploadMode(hasActiveData ? null : 'clear');
  };

  const canUpload = selectedFile && uploadMode !== null && !uploading && !uploadResult;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white border border-[#E2E8F0] rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col text-[#0F172A] max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-[#E2E8F0] flex items-center justify-between bg-[#F8FAFC]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0] text-[#059669]">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#0F172A] tracking-tight">
                Log Telemetry Ingestion &amp; Parser
              </h2>
              <p className="text-xs text-[#64748B]">
                Upload CSV or JSON logs with automatic timestamp normalization.
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
          {!uploadResult ? (
            <>
              {/* Drag & Drop File Zone */}
              <div>
                <div
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-xl p-6 text-center transition-all ${
                    dragActive
                      ? 'border-[#10B981] bg-[#ECFDF5]'
                      : 'border-[#E2E8F0] bg-[#F8FAFC] hover:border-[#10B981]/60 hover:bg-white'
                  }`}
                >
                  <input
                    type="file"
                    id="file-upload-input"
                    accept=".csv,.json"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  <label htmlFor="file-upload-input" className="cursor-pointer block space-y-2">
                    <div className="mx-auto w-10 h-10 rounded-full bg-white border border-[#E2E8F0] flex items-center justify-center text-[#10B981] shadow-subtle">
                      {selectedFile?.name.endsWith('.csv') ? (
                        <FileSpreadsheet className="w-5 h-5 text-[#10B981]" />
                      ) : selectedFile?.name.endsWith('.json') ? (
                        <FileText className="w-5 h-5 text-[#0284C7]" />
                      ) : (
                        <Upload className="w-5 h-5 text-[#64748B]" />
                      )}
                    </div>
                    <div>
                      <span className="text-[#0F172A] font-semibold text-sm">
                        {selectedFile ? selectedFile.name : 'Click to select or drag & drop log file'}
                      </span>
                      <p className="text-[11px] text-[#64748B] mt-0.5">
                        Accepts raw syslog, auth logs, Apache, firewall, or security event telemetry (CSV/JSON).
                      </p>
                    </div>
                  </label>
                </div>
              </div>

              {/* Automatic Timestamp Normalization Indicator (Phase 6A requirement: no manual date format selection) */}
              <div className="rounded-xl border border-[#D1FAE5] bg-[#F0FDF4] p-3 text-[11px] flex items-start gap-2.5 text-[#065F46]">
                <ShieldCheck className="w-4 h-4 text-[#059669] shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-bold text-[#065F46] block">Automatic Timestamp Normalization Active</span>
                  <span className="text-[#047857] leading-relaxed">
                    TraceX automatically parses ISO 8601, syslog dates, epoch timestamps, and UTC offsets. Ambiguous formats are recorded honestly without silently fabricating dates.
                  </span>
                </div>
              </div>

              {/* Upload Mode Selector — only shown when there's already active data and a file is selected */}
              {hasActiveData && selectedFile && (
                <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-subtle">
                  <div className="px-3 py-2 bg-[#FFFBEB] border-b border-[#FEF3C7] flex items-center gap-2 text-[11px] text-[#B45309]">
                    <Info className="w-3.5 h-3.5 shrink-0" />
                    <span>An active investigation exists. How should TraceX handle this file?</span>
                  </div>
                  <div className="grid grid-cols-2 divide-x divide-[#E2E8F0]">
                    <button
                      id="upload-mode-append"
                      type="button"
                      onClick={() => setUploadMode('append')}
                      className={`p-3 text-left transition-all ${
                        uploadMode === 'append'
                          ? 'bg-[#ECFDF5] ring-2 ring-inset ring-[#10B981]'
                          : 'bg-white hover:bg-[#F8FAFC]'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold text-[#059669] mb-1">
                        <PlusCircle className="w-3.5 h-3.5" />
                        <span>Add to Existing Data</span>
                      </div>
                      <p className="text-[10px] text-[#64748B] leading-snug">
                        Append new events. Duplicates are deduplicated. Correlations recalculate automatically.
                      </p>
                    </button>

                    <button
                      id="upload-mode-clear"
                      type="button"
                      onClick={() => setUploadMode('clear')}
                      className={`p-3 text-left transition-all ${
                        uploadMode === 'clear'
                          ? 'bg-[#FEF2F2] ring-2 ring-inset ring-[#DC2626]'
                          : 'bg-white hover:bg-[#F8FAFC]'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold text-[#DC2626] mb-1">
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Clear &amp; Load New</span>
                      </div>
                      <p className="text-[10px] text-[#64748B] leading-snug">
                        Fresh investigation. Clears existing telemetry while preserving saved cases.
                      </p>
                    </button>
                  </div>
                </div>
              )}

              {/* Validation & Error Display */}
              {errorMessage && (
                <div className="p-3 rounded-lg bg-[#FEF2F2] border border-[#FECACA] text-[#DC2626] flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-[#DC2626] shrink-0 mt-0.5" />
                  <div>
                    <strong className="block text-[#DC2626]">Parsing Validation Error:</strong>
                    <span className="text-[11px] text-[#991B1B]">{errorMessage}</span>
                  </div>
                </div>
              )}
            </>
          ) : (
            /* Comprehensive Ingestion Statistics Report (Phase 6C requirement) */
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-[#ECFDF5] border border-[#A7F3D0] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-[#065F46] text-sm">
                    <CheckCircle2 className="w-5 h-5 text-[#10B981]" />
                    <span>Ingestion &amp; Normalization Complete</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white text-[#059669] border border-[#A7F3D0] font-bold">
                    {uploadResult.filename}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono">
                  <div className="p-2.5 rounded-lg bg-white border border-[#D1FAE5]">
                    <span className="text-[10px] text-[#64748B] block font-sans font-medium">Parsed Events</span>
                    <strong className="text-base text-[#0F172A]">{uploadResult.parsed_events_count}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white border border-[#D1FAE5]">
                    <span className="text-[10px] text-[#64748B] block font-sans font-medium">Normalized Timestamps</span>
                    <strong className="text-base text-[#059669]">{uploadResult.timestamps_normalized ?? uploadResult.parsed_events_count}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white border border-[#D1FAE5]">
                    <span className="text-[10px] text-[#64748B] block font-sans font-medium">Correlated Alerts</span>
                    <strong className="text-base text-[#D97706]">{uploadResult.new_alerts_generated}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-white border border-[#D1FAE5]">
                    <span className="text-[10px] text-[#64748B] block font-sans font-medium">Duplicates Skipped</span>
                    <strong className="text-base text-[#64748B]">{uploadResult.duplicates_skipped ?? 0}</strong>
                  </div>
                </div>

                {/* Additional timestamp telemetry breakdown */}
                <div className="grid grid-cols-3 gap-2 text-[11px] font-mono pt-1 text-[#475569]">
                  <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                    Ambiguous Dates: <strong className={uploadResult.timestamps_ambiguous > 0 ? 'text-[#D97706]' : 'text-[#64748B]'}>{uploadResult.timestamps_ambiguous || 0}</strong>
                  </div>
                  <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                    Unparsed Timestamps: <strong className={uploadResult.timestamps_unparsed > 0 ? 'text-[#DC2626]' : 'text-[#64748B]'}>{uploadResult.timestamps_unparsed || 0}</strong>
                  </div>
                  <div className="bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                    Total DB Records: <strong className="text-[#0F172A]">{uploadResult.total_database_events}</strong>
                  </div>
                </div>

                {uploadResult.errors?.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-[#FFFBEB] border border-[#FDE68A] text-[#92400E] text-[11px] space-y-1">
                    <span className="font-bold block">Warnings &amp; Parser Notices:</span>
                    <ul className="list-disc list-inside space-y-0.5">
                      {uploadResult.errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-[#64748B] hover:text-[#0F172A] bg-white hover:bg-[#F1F5F9] border border-[#E2E8F0] transition font-medium"
          >
            {uploadResult ? 'Done / Close' : 'Cancel'}
          </button>

          {!uploadResult ? (
            <button
              id="upload-correlate-btn"
              onClick={handleUpload}
              disabled={!canUpload}
              className="px-4 py-1.5 rounded-lg font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-subtle transition disabled:opacity-50 flex items-center gap-1.5"
            >
              {uploading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>{uploading ? 'Parsing & Normalizing...' : 'Upload & Ingest'}</span>
            </button>
          ) : (
            <button
              onClick={handleResetForNewFile}
              className="px-4 py-1.5 rounded-lg font-semibold bg-white hover:bg-[#F1F5F9] text-[#0F172A] border border-[#CBD5E1] transition shadow-subtle"
            >
              Upload Another File
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
