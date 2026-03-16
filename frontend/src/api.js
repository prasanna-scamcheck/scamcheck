/**
 * ScamCheck API Client
 * Handles all communication between React frontend and FastAPI backend.
 */

const API_BASE = process.env.REACT_APP_API_URL || "/api";

async function apiFetch(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Search ──
export async function searchIndicator(query) {
  return apiFetch(`/search?q=${encodeURIComponent(query)}`);
}

// ── Indicators ──
export async function listIndicators(page = 1, limit = 20, type = null, sort = "risk_score") {
  let url = `/indicators?page=${page}&limit=${limit}&sort=${sort}`;
  if (type) url += `&type=${type}`;
  return apiFetch(url);
}

export async function getIndicator(id) {
  return apiFetch(`/indicators/${id}`);
}

// ── Reports ──
export async function submitReport(report) {
  return apiFetch("/reports", {
    method: "POST",
    body: JSON.stringify(report),
  });
}

export async function getPendingReports() {
  return apiFetch("/reports/pending");
}

export async function approveReport(id) {
  return apiFetch(`/reports/${id}/approve`, { method: "POST" });
}

export async function rejectReport(id) {
  return apiFetch(`/reports/${id}/reject`, { method: "POST" });
}

// ── Stats & Trends ──
export async function getDashboardStats() {
  return apiFetch("/stats");
}

export async function getFraudTrends() {
  return apiFetch("/trends");
}

// ── Health ──
export async function healthCheck() {
  return apiFetch("/health");
}

// ── Scam Predictor ──
export async function predictScam(message) {
  return apiFetch("/predict", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export async function getScamLibrary() {
  return apiFetch("/scam-library");
}

export async function getScamDetail(scamId) {
  return apiFetch(`/scam-library/${scamId}`);
}

export async function getScamRadar() {
  return apiFetch("/scam-radar");
}
