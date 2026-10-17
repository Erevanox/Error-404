const API_BASE = '/api';

export const apiClient = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  async getStats() {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) throw new Error('Failed to fetch SOC stats');
    return res.json();
  },

  async getEvents({ category, severityMin, search, limit = 500 } = {}) {
    const params = new URLSearchParams();
    if (category && category !== 'ALL') params.append('category', category);
    if (severityMin !== undefined && severityMin !== null) params.append('severity_min', severityMin);
    if (search) params.append('search', search);
    params.append('limit', limit);

    const res = await fetch(`${API_BASE}/events?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch events');
    return res.json();
  },

  async getScatterEvents({ category, severityMin, search } = {}) {
    const params = new URLSearchParams();
    if (category && category !== 'ALL') params.append('category', category);
    if (severityMin !== undefined && severityMin !== null) params.append('severity_min', severityMin);
    if (search) params.append('search', search);

    const res = await fetch(`${API_BASE}/events/scatter?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch scatter points');
    return res.json();
  },

  async getEventById(eventId) {
    const res = await fetch(`${API_BASE}/events/${eventId}`);
    if (!res.ok) throw new Error(`Event ${eventId} not found`);
    return res.json();
  },

  async getAlerts() {
    const res = await fetch(`${API_BASE}/alerts`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async getAlertById(alertId) {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`);
    if (!res.ok) throw new Error(`Alert ${alertId} not found`);
    return res.json();
  },

  async uploadFile(file, mode = 'append', dateFormat = 'auto', timeFormat = 'auto') {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('mode', mode);
    formData.append('date_format', dateFormat);
    formData.append('time_format', timeFormat);
    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    if (!res.ok) {
      const errDetail = Array.isArray(data.errors) ? data.errors.join('; ') : (data.message || data.detail || 'Upload failed');
      throw new Error(errDetail);
    }
    return data;
  },

  async resetDemo() {
    const res = await fetch(`${API_BASE}/reset-demo`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to reset demo dataset');
    return res.json();
  },

  async loadSample(scenario) {
    const res = await fetch(`${API_BASE}/load-sample/${scenario}`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to load ${scenario} scenario`);
    return res.json();
  },

  async getCases() {
    const res = await fetch(`${API_BASE}/cases`);
    if (!res.ok) throw new Error('Failed to fetch cases');
    return res.json();
  },

  async getCaseById(caseId) {
    const res = await fetch(`${API_BASE}/cases/${caseId}`);
    if (!res.ok) throw new Error(`Case ${caseId} not found`);
    return res.json();
  },

  async createCase(caseData) {
    const res = await fetch(`${API_BASE}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(caseData),
    });
    if (!res.ok) throw new Error('Failed to create investigation case');
    return res.json();
  },

  async updateCase(caseId, updateData) {
    const res = await fetch(`${API_BASE}/cases/${caseId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateData),
    });
    if (!res.ok) throw new Error('Failed to update case');
    return res.json();
  },

  async addCaseNote(caseId, noteData) {
    const res = await fetch(`${API_BASE}/cases/${caseId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(noteData),
    });
    if (!res.ok) throw new Error('Failed to add case note');
    return res.json();
  },

  async simulatePlaybook(data) {
    const res = await fetch(`${API_BASE}/playbooks/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to execute simulated playbook');
    return res.json();
  },

  async getPlaybookHistory() {
    const res = await fetch(`${API_BASE}/playbooks/history`);
    if (!res.ok) throw new Error('Failed to fetch playbook history');
    return res.json();
  },

  async clearData() {
    const res = await fetch(`${API_BASE}/clear`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to clear telemetry dataset');
    return res.json();
  },

  getPdfUrl(alertId) {
    return alertId ? `${API_BASE}/reports/pdf/${alertId}` : `${API_BASE}/reports/pdf`;
  },

  getCsvUrl() {
    return `${API_BASE}/reports/csv`;
  }
};
