const API_BASE = "http://localhost:8000/api";
const M1_BASE = "http://localhost:8001";

export async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const token = localStorage.getItem("forensight_token");
  const headers = {
    ...(options.headers || {}),
  };
  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const res = await fetch(url, { ...options, headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Request failed with status ${res.status}`);
    }
    return await res.json();
  } catch (error) {
    console.error(`API Error on ${endpoint}:`, error);
    throw error;
  }
}

// Authentication & Profile
export const loginUser = (email, password) =>
  request("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

export const getCurrentUser = () => request("/auth/me");

// Module 1: Case Management
export const getCases = () => request("/cases");
export const getCase = (caseId) => request(`/cases/${caseId}`);
export const getCaseStats = (caseId) => request(`/cases/${caseId}/stats`);
export const createCase = (data) =>
  request("/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
export const getAuditLogs = (caseId) => request(`/cases/${caseId}/audit-logs`);

// Module 1 & 2: Evidence Management, Ingestion & Processing
export const getEvidence = (caseId) => request(`/cases/${caseId}/evidence`);
export const getCaseArtifacts = (caseId) => request(`/cases/${caseId}/artifacts`);
export const getEvidenceArtifacts = (evidenceId) => request(`/evidence/${evidenceId}/artifacts`);
export const verifyEvidenceIntegrity = (evidenceId) =>
  request(`/evidence/${evidenceId}/verify-integrity`, { method: "POST" });

export const uploadEvidence = async (caseId, file, evidenceType) => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("evidence_type", evidenceType);
  const token = localStorage.getItem("forensight_token");
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/upload`, {
    method: "POST",
    headers,
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(err.detail || "Evidence upload failed");
  }
  return res.json();
};

export const processEvidence = (evidenceId, params = {}) => {
  const query = new URLSearchParams();
  if (params.kind) query.append("kind", params.kind);
  if (params.timeline !== undefined) query.append("timeline", params.timeline);
  if (params.run_analysis !== undefined) query.append("run_analysis", params.run_analysis);
  const qStr = query.toString();
  return request(`/evidence/${evidenceId}/process${qStr ? `?${qStr}` : ""}`, {
    method: "POST",
  });
};

export const processCaseEvidence = (caseId) =>
  request(`/cases/${caseId}/process`, { method: "POST" });

export const getEvidenceStatus = (evidenceId) =>
  request(`/evidence/${evidenceId}/status`);

// Forensic Tools Integration (M1 with M3 Fallback)
export const getForensicTools = async () => {
  try {
    const res = await fetch(`${M1_BASE}/tools`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data = await res.json();
      return data.tools || data;
    }
  } catch {
    // M1 direct call failed or timed out, fallback to M3
  }
  const fallback = await request("/system/tools");
  return fallback.tools || fallback;
};

// Module 3: Timeline & Forensic Analysis
export const getTimeline = (caseId, params = {}) => {
  const query = new URLSearchParams();
  if (params.event_type) query.append("event_type", params.event_type);
  if (params.user_account) query.append("user_account", params.user_account);
  if (params.host_ip) query.append("host_ip", params.host_ip);
  if (params.only_anomalous) query.append("only_anomalous", "true");
  if (params.search) query.append("search", params.search);
  return request(`/cases/${caseId}/timeline?${query.toString()}`);
};

// Module 4: AI Investigation Assistant
export const queryAI = (caseId, queryText) =>
  request("/ai/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId, query: queryText }),
  });
export const getAISummary = (caseId) => request(`/ai/cases/${caseId}/summary`);

// Module 5: Attack-Path Reconstruction & Validation Gate
export const getAttackPath = (caseId) => request(`/cases/${caseId}/attack-path`);
export const getFindings = (caseId) => request(`/cases/${caseId}/findings`);
export const validateFinding = (findingId, data) =>
  request(`/findings/${findingId}/validate`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
export const runCorrelation = (caseId) =>
  request(`/cases/${caseId}/correlate`, { method: "POST" });

// Module 6 & 7: Report Generation & Two-Key Encrypted Vault
export const getReports = (caseId) => request(`/cases/${caseId}/reports`);
export const generateReport = (caseId, data) =>
  request(`/cases/${caseId}/reports/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
export const decryptReport = (reportId) => request(`/reports/${reportId}/decrypt`);

// System Seeding
export const reseedDatabase = () => request("/system/seed", { method: "POST" });
