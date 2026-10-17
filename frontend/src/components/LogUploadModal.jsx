import React, { useState, useEffect } from 'react';
import { 
  X, Upload, FileText, CheckCircle2, AlertTriangle, 
  RefreshCw, FileSpreadsheet, PlusCircle, Info, Calendar, Clock, SlidersHorizontal
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

  // Format selection states
  const [dateFormat, setDateFormat] = useState('auto');
  const [timeFormat, setTimeFormat] = useState('auto');

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
      const res = await apiClient.uploadFile(selectedFile, uploadMode, dateFormat, timeFormat);
      setUploadResult(res);
      if (onUploadSuccess) onUploadSuccess();
      onClose(); // Close modal immediately upon completion
    } catch (err) {
      setErrorMessage(err.message || 'File upload failed. Check format.');
    } finally {
      setUploading(false);
    }
  };

  const canUpload = selectedFile && uploadMode !== null && !uploading;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white border border-[#E2E8F0] rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col text-[#0F172A]">
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
                Upload CSV or JSON logs with configurable normalization rules.
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
        <div className="p-5 space-y-4 text-xs max-h-[75vh] overflow-y-auto">
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
                </div>
              </label>
            </div>
          </div>

          {/* Normalization Format Options (User selectable Date & Time Formats) */}
          <div className="rounded-xl border border-[#E2E8F0] bg-[#F8FAFC] p-3.5 space-y-3">
            <div className="flex items-center gap-1.5 text-[#0F172A] font-semibold text-xs">
              <SlidersHorizontal className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Normalization Format Settings</span>
              <span className="text-[10px] text-[#64748B] font-normal ml-auto">(Configures timestamp parsing)</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Date Format Selector */}
              <div className="space-y-1">
                <label className="flex items-center gap-1.5 text-[11px] font-medium text-[#475569]">
                  <Calendar className="w-3.5 h-3.5 text-[#059669]" />
                  <span>Date Format</span>
                </label>
                <select
                  value={dateFormat}
                  onChange={(e) => setDateFormat(e.target.value)}
                  className="w-full text-xs bg-white border border-[#CBD5E1] rounded-lg px-2.5 py-1.5 text-[#0F172A] focus:outline-none focus:ring-1 focus:ring-[#10B981] focus:border-[#10B981] transition shadow-subtle"
                >
                  <option value="auto">Auto-Detect Format (Recommended)</option>
                  <option value="YYYY-MM-DD">YYYY-MM-DD (e.g., 2026-10-16)</option>
                  <option value="DD/MM/YYYY">DD/MM/YYYY (e.g., 16/10/2026)</option>
                  <option value="MM/DD/YYYY">MM/DD/YYYY (e.g., 10/16/2026)</option>
                  <option value="YYYY/MM/DD">YYYY/MM/DD (e.g., 2026/10/16)</option>
                  <option value="syslog">Syslog / Apache (e.g., Oct 16 02:14:10)</option>
                </select>
              </div>

              {/* Time Format Selector */}
              <div className="space-y-1">
                <label className="flex items-center gap-1.5 text-[11px] font-medium text-[#475569]">
                  <Clock className="w-3.5 h-3.5 text-[#2563EB]" />
                  <span>Time Format</span>
                </label>
                <select
                  value={timeFormat}
                  onChange={(e) => setTimeFormat(e.target.value)}
                  className="w-full text-xs bg-white border border-[#CBD5E1] rounded-lg px-2.5 py-1.5 text-[#0F172A] focus:outline-none focus:ring-1 focus:ring-[#10B981] focus:border-[#10B981] transition shadow-subtle"
                >
                  <option value="auto">Auto-Detect Format (Recommended)</option>
                  <option value="24h">24-Hour (HH:mm:ss / HH:mm)</option>
                  <option value="12h">12-Hour AM/PM (hh:mm:ss a)</option>
                  <option value="epoch">Unix Epoch (seconds / ms)</option>
                </select>
              </div>
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

          {/* Upload Success Report */}
          {uploadResult && (
            <div className="p-3.5 rounded-xl bg-[#ECFDF5] border border-[#A7F3D0] text-[#059669] space-y-1.5">
              <div className="flex items-center gap-2 font-bold text-[#059669]">
                <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                <span>Ingestion &amp; Normalization Complete</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1 text-[#0F172A]">
                <div>Parsed Events: <strong>{uploadResult.parsed_events_count}</strong></div>
                <div>New Correlated Alerts: <strong className="text-[#059669]">{uploadResult.new_alerts_generated}</strong></div>
              </div>
              {uploadResult.errors?.length > 0 && (
                <div className="pt-2 text-[10px] text-[#D97706] border-t border-[#A7F3D0]">
                  <span>Warnings: {uploadResult.errors.join('; ')}</span>
                </div>
              )}
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
            Close
          </button>

          <button
            id="upload-correlate-btn"
            onClick={handleUpload}
            disabled={!canUpload}
            className="px-4 py-1.5 rounded-lg font-semibold bg-[#10B981] hover:bg-[#059669] text-white shadow-subtle transition disabled:opacity-50"
          >
            {uploading
              ? 'Parsing & Normalizing...'
              : uploadMode === 'append'
              ? 'Append & Correlate'
              : 'Upload & Correlate'}
          </button>
        </div>
      </div>
    </div>
  );
}
