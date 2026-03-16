import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  searchIndicator, listIndicators, submitReport,
  getPendingReports, approveReport, rejectReport,
  getDashboardStats, getFraudTrends,
  predictScam, getScamLibrary, getScamDetail
} from "./api";
import { PrivacyPolicy, TermsOfService, DataSources, Disclaimer } from "./LegalPages";
import "./App.css";
import "./LegalStyles.css";

/* ─── CONSTANTS ─── */
const SCAM_CATEGORIES = [
  "Investment Fraud", "UPI Fraud", "Phishing", "Loan Scam", "Job Scam",
  "Tech Support Scam", "Romance Scam", "Lottery Scam", "KYC Fraud",
  "Fake E-commerce", "Crypto Scam", "OTP Fraud", "Sextortion",
  "Impersonation", "Advance Fee Fraud"
];
const STATES = [
  "Maharashtra", "Delhi", "Karnataka", "Tamil Nadu", "Uttar Pradesh",
  "Gujarat", "Rajasthan", "West Bengal", "Telangana", "Kerala",
  "Madhya Pradesh", "Bihar", "Andhra Pradesh", "Punjab", "Haryana"
];

/* ─── HELPERS ─── */
const getRiskLevel = (score) => {
  if (score <= 20) return { label: "Safe", color: "#22c55e", bg: "#052e16" };
  if (score <= 50) return { label: "Suspicious", color: "#eab308", bg: "#422006" };
  if (score <= 80) return { label: "High Risk", color: "#f97316", bg: "#431407" };
  return { label: "Confirmed Fraud", color: "#ef4444", bg: "#450a0a" };
};
const getTypeIcon = (type) => ({ phone: "📱", upi: "₹", bank_account: "🏦", email: "✉️", domain: "🌐", wallet: "🪙" }[type] || "🔍");
const getTypeLabel = (type) => ({ phone: "Phone", upi: "UPI ID", bank_account: "Bank Account", email: "Email", domain: "Domain", wallet: "Crypto Wallet" }[type] || type);

export default function App() {
  const [page, setPage] = useState("home");
  const [query, setQuery] = useState("");
  const [searchResult, setSearchResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Admin state
  const [adminTab, setAdminTab] = useState("moderation");
  const [pendingReports, setPendingReports] = useState([]);
  const [allIndicators, setAllIndicators] = useState([]);
  const [dashStats, setDashStats] = useState(null);
  const [trends, setTrends] = useState(null);

  // Report form
  const [reportForm, setReportForm] = useState({
    indicator_value: "", indicator_type: "phone", category: SCAM_CATEGORIES[0],
    description: "", city: "", state: STATES[0]
  });
  const [reportSubmitted, setReportSubmitted] = useState(false);
  const [showConsent, setShowConsent] = useState(true);

  // Scam Predictor state
  const [predictorMessage, setPredictorMessage] = useState("");
  const [prediction, setPrediction] = useState(null);
  const [scamLibrary, setScamLibrary] = useState([]);

  const searchRef = useRef(null);

  /* ─── SEARCH ─── */
  const doSearch = useCallback(async (q) => {
    const val = (q || query).trim();
    if (!val) return;
    setLoading(true);
    setError(null);
    try {
      const data = await searchIndicator(val);
      setSearchResult(data);
      setPage("result");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* ─── ADMIN DATA LOADERS ─── */
  const loadAdminData = useCallback(async () => {
    try {
      const [pending, inds, stats, trendData] = await Promise.all([
        getPendingReports(),
        listIndicators(1, 50),
        getDashboardStats(),
        getFraudTrends(),
      ]);
      setPendingReports(pending);
      setAllIndicators(inds.indicators);
      setDashStats(stats);
      setTrends(trendData);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    if (page === "admin") loadAdminData();
  }, [page, loadAdminData]);

  /* ─── HANDLERS ─── */
  const handleSearchKey = (e) => { if (e.key === "Enter") doSearch(); };
  const goHome = () => { setPage("home"); setQuery(""); setSearchResult(null); setError(null); };

  const handlePredict = async () => {
    if (!predictorMessage.trim() || predictorMessage.length < 5) return;
    setLoading(true);
    setError(null);
    try {
      const result = await predictScam(predictorMessage);
      setPrediction(result);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    if (page === "predictor" && scamLibrary.length === 0) {
      getScamLibrary().then(setScamLibrary).catch(() => {});
    }
  }, [page, scamLibrary.length]);

  const handleReportSubmit = async () => {
    if (!reportForm.indicator_value || !reportForm.description) return;
    setLoading(true);
    try {
      await submitReport(reportForm);
      setReportForm({ indicator_value: "", indicator_type: "phone", category: SCAM_CATEGORIES[0], description: "", city: "", state: STATES[0] });
      setReportSubmitted(true);
      setTimeout(() => setReportSubmitted(false), 4000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (id) => {
    try {
      await approveReport(id);
      setPendingReports(prev => prev.filter(r => r.id !== id));
      // Reload stats
      const stats = await getDashboardStats();
      setDashStats(stats);
    } catch (err) { setError(err.message); }
  };

  const handleReject = async (id) => {
    try {
      await rejectReport(id);
      setPendingReports(prev => prev.filter(r => r.id !== id));
    } catch (err) { setError(err.message); }
  };

  /* ═══ RENDER ═══ */
  return (
    <div className="app">
      <div className="grid-bg" />

      {/* NAV */}
      <nav className="nav">
        <div className="nav-brand" onClick={goHome}>
          <div className="shield">🛡</div>
          <span>ScamCheck</span>
        </div>
        <div className="nav-links">
          <button className={`nav-link ${page === "home" ? "active" : ""}`} onClick={goHome}>Search</button>
          <button className={`nav-link ${page === "predictor" ? "active" : ""}`} onClick={() => setPage("predictor")}>Scam Predictor</button>
          <button className={`nav-link ${page === "report" ? "active" : ""}`} onClick={() => { setPage("report"); setReportSubmitted(false); }}>Report Scam</button>
          <button className={`nav-link ${page === "admin" ? "active" : ""}`} onClick={() => setPage("admin")}>Dashboard</button>
        </div>
      </nav>

      {/* ERROR BANNER */}
      {error && (
        <div style={{ maxWidth: 640, margin: "16px auto", padding: "12px 20px", borderRadius: 10, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "#ef4444", fontSize: 13, textAlign: "center" }}>
          {error} <button onClick={() => setError(null)} style={{ marginLeft: 12, background: "none", border: "none", color: "#ef4444", cursor: "pointer", textDecoration: "underline" }}>dismiss</button>
        </div>
      )}

      {/* ─── HOME ─── */}
      {page === "home" && (
        <div style={{ position: "relative", zIndex: 1 }}>
          <div className="hero">
            <div className="hero-badge fade-up">⚡ Cybercrime Intelligence Engine</div>
            <h1 className="fade-up-d1">
              Verify before you<br /><span className="highlight">trust or pay</span>
            </h1>
            <p className="fade-up-d2">
              Search any phone number, UPI ID, bank account, email, or website to check
              if it's linked to cyber fraud reports across India.
            </p>
            <div className="search-container fade-up-d2">
              <input
                ref={searchRef}
                className="search-box"
                placeholder="Search phone, UPI, bank account, email, or domain..."
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleSearchKey}
                disabled={loading}
              />
              <button className="search-btn" onClick={() => doSearch()} disabled={loading}>
                {loading ? "..." : "→"}
              </button>
            </div>
            <div className="search-hint fade-up-d3">
              {["+91 98765 43210", "investhelp@okaxis", "quickprofit-invest.in", "sbi.kyc.update@gmail.com"].map(h => (
                <span key={h} className="hint-chip" onClick={() => { setQuery(h); doSearch(h); }}>{h}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ─── RESULT ─── */}
      {page === "result" && searchResult && searchResult.found && searchResult.result && (() => {
        const r = searchResult.result;
        const risk = getRiskLevel(r.risk_score);
        const linked = r.linked_indicators || [];
        return (
          <div className="result-page">
            <div className="result-header fade-up">
              <div className="result-icon" style={{ background: risk.bg, border: `1.5px solid ${risk.color}30` }}>
                {getTypeIcon(r.type)}
              </div>
              <div>
                <div className="result-value mono">{r.value}</div>
                <span className="result-type-badge">{getTypeLabel(r.type)}</span>
              </div>
              <span className="risk-badge" style={{ background: risk.bg, color: risk.color, border: `1.5px solid ${risk.color}40` }}>
                {risk.label}
              </span>
            </div>

            {/* Risk Score */}
            <div className="card fade-up-d1">
              <div className="card-title">Risk Assessment</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 14 }}>
                <span className="mono" style={{ fontSize: 36, fontWeight: 700, color: risk.color }}>{r.risk_score}</span>
                <span style={{ fontSize: 14, color: "var(--text-muted)" }}>/ 100</span>
              </div>
              <div className="score-bar-track">
                <div className="score-bar-fill" style={{ width: `${r.risk_score}%`, background: `linear-gradient(90deg, ${risk.color}90, ${risk.color})` }} />
              </div>
              <div className="score-labels">
                <span>0 Safe</span><span>50 Suspicious</span><span>80 High Risk</span><span>100 Fraud</span>
              </div>
            </div>

            {/* Intel Summary */}
            <div className="card fade-up-d1">
              <div className="card-title">Intelligence Summary</div>
              <div className="intel-grid">
                {[
                  ["Complaints", r.complaint_count, "var(--danger)"],
                  ["Scam Type", r.category, null],
                  ["Location", r.location, null],
                  ["Status", r.status, null],
                  ["First Seen", r.first_seen?.split("T")[0], null],
                  ["Last Seen", r.last_seen?.split("T")[0], null],
                ].map(([label, value, color]) => (
                  <div key={label} className="intel-cell">
                    <div className="intel-cell-label">{label}</div>
                    <div className="intel-cell-value" style={{ fontSize: typeof value === "number" ? 14 : 12, color: color || "var(--text-primary)", textTransform: label === "Status" ? "capitalize" : "none" }}>
                      {value || "—"}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Notes */}
            {r.notes && (
              <div className="card fade-up-d2">
                <div className="card-title">Analyst Notes</div>
                <div className="notes-text">{r.notes}</div>
              </div>
            )}

            {/* Linked Intelligence */}
            {linked.length > 0 && (
              <div className="card fade-up-d2">
                <div className="card-title">🔗 Linked Intelligence ({linked.length} connected indicators)</div>
                {linked.map(l => {
                  const lr = getRiskLevel(l.risk_score);
                  return (
                    <div key={l.id} className="linked-item" onClick={() => { setQuery(l.value); doSearch(l.value); window.scrollTo(0, 0); }}>
                      <span style={{ fontSize: 20 }}>{getTypeIcon(l.type)}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{l.value}</div>
                        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{getTypeLabel(l.type)} · {l.complaint_count} reports</div>
                      </div>
                      <span className="linked-badge" style={{ background: lr.bg, color: lr.color }}>{lr.label}</span>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Recommendation */}
            {searchResult.recommendation && (
              <div className="action-banner fade-up-d3" style={{
                borderColor: r.risk_score > 80 ? "var(--danger)" : r.risk_score > 50 ? "var(--high-risk)" : "var(--safe)",
                background: r.risk_score > 80 ? "rgba(239,68,68,0.06)" : r.risk_score > 50 ? "rgba(249,115,22,0.06)" : "rgba(34,197,94,0.06)"
              }}>
                <div className="icon">{r.risk_score > 80 ? "🚨" : r.risk_score > 50 ? "⚠️" : "✅"}</div>
                <div className="text">
                  <strong>Recommendation</strong>
                  {searchResult.recommendation}
                </div>
              </div>
            )}

            <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
              <button className="submit-btn" style={{ flex: 1 }} onClick={() => setPage("report")}>Report This Scam</button>
              <button className="submit-btn secondary" style={{ flex: 1 }} onClick={goHome}>New Search</button>
            </div>
          </div>
        );
      })()}

      {/* Not Found */}
      {page === "result" && searchResult && !searchResult.found && (
        <div className="not-found fade-up">
          <div className="icon">🔍</div>
          <h3>No reports found</h3>
          <p>
            <span className="mono" style={{ color: "var(--safe)" }}>"{searchResult.query}"</span> has no fraud reports in our database.
            {searchResult.detected_type && <><br />Detected as: <strong>{getTypeLabel(searchResult.detected_type)}</strong></>}
            <br /><br />
            This doesn't guarantee safety. Always verify independently.
          </p>
          <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
            <button className="submit-btn" style={{ width: "auto", padding: "12px 28px" }} onClick={() => setPage("report")}>Report if suspicious</button>
            <button className="submit-btn secondary" style={{ width: "auto", padding: "12px 28px" }} onClick={goHome}>New Search</button>
          </div>
        </div>
      )}

      {/* ─── REPORT ─── */}
      {page === "report" && (
        <div className="report-page">
          <h2 className="fade-up">Report a Scam</h2>
          <p className="subtitle fade-up">Help protect others. Your report enters a moderation queue and will be verified before publishing.</p>

          {reportSubmitted && (
            <div className="success-msg fade-up">✅ Report submitted successfully. It will be reviewed by our moderation team.</div>
          )}

          <div className="card fade-up-d1">
            <div className="form-group">
              <label className="form-label">Suspicious Indicator *</label>
              <input className="form-input mono" placeholder="Phone, UPI, email, domain, bank account..."
                value={reportForm.indicator_value}
                onChange={e => setReportForm(p => ({ ...p, indicator_value: e.target.value }))} />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Indicator Type</label>
                <select className="form-select" value={reportForm.indicator_type}
                  onChange={e => setReportForm(p => ({ ...p, indicator_type: e.target.value }))}>
                  {[["phone","Phone Number"],["upi","UPI ID"],["bank_account","Bank Account"],["email","Email"],["domain","Domain/Website"],["wallet","Crypto Wallet"]].map(([v,l]) => (
                    <option key={v} value={v}>{l}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Scam Category</label>
                <select className="form-select" value={reportForm.category}
                  onChange={e => setReportForm(p => ({ ...p, category: e.target.value }))}>
                  {SCAM_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">What happened? *</label>
              <textarea className="form-textarea" placeholder="Describe the scam — how were you contacted, what did they ask for, did you lose money?"
                value={reportForm.description}
                onChange={e => setReportForm(p => ({ ...p, description: e.target.value }))} />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">City</label>
                <input className="form-input" placeholder="Your city" value={reportForm.city}
                  onChange={e => setReportForm(p => ({ ...p, city: e.target.value }))} />
              </div>
              <div className="form-group">
                <label className="form-label">State</label>
                <select className="form-select" value={reportForm.state}
                  onChange={e => setReportForm(p => ({ ...p, state: e.target.value }))}>
                  {STATES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>

            <button className="submit-btn" onClick={handleReportSubmit}
              disabled={!reportForm.indicator_value || !reportForm.description || loading}>
              {loading ? "Submitting..." : "Submit Fraud Report"}
            </button>
          </div>

          <div className="info-box">
            <strong>What happens next?</strong><br />
            Your report enters our moderation queue. Verified reports contribute to the risk score and help protect future victims.
            <br /><br />
            <strong>Immediate help:</strong> If you've lost money, report to <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a> or call <span className="mono accent">1930</span>.
          </div>
        </div>
      )}

      {/* ─── ADMIN DASHBOARD ─── */}
      {page === "admin" && (
        <div className="admin-page">
          <h2 className="fade-up">Intelligence Dashboard</h2>

          {dashStats && (
            <div className="admin-stats fade-up-d1">
              {[
                [dashStats.total_indicators, "Total Indicators", "var(--accent)"],
                [dashStats.confirmed_fraud, "Confirmed Fraud", "var(--danger)"],
                [dashStats.pending_reports, "Pending Reports", "var(--suspicious)"],
                [dashStats.total_reports, "Total Complaints", "var(--info)"],
              ].map(([num, label, color]) => (
                <div key={label} className="admin-stat-card">
                  <div className="num mono" style={{ color }}>{num}</div>
                  <div className="label">{label}</div>
                </div>
              ))}
            </div>
          )}

          <div className="admin-tabs fade-up-d1">
            {[["moderation","Moderation Queue"],["indicators","All Indicators"],["trends","Fraud Trends"]].map(([k,l]) => (
              <button key={k} className={`admin-tab ${adminTab === k ? "active" : ""}`} onClick={() => setAdminTab(k)}>{l}</button>
            ))}
          </div>

          {/* Moderation Queue */}
          {adminTab === "moderation" && (
            <div className="fade-up-d2">
              {pendingReports.length === 0 ? (
                <div className="empty-state">
                  <div style={{ fontSize: 36, marginBottom: 12 }}>✅</div>
                  All reports have been reviewed. Queue is empty.
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>ID</th><th>Indicator</th><th>Type</th><th>Category</th><th>Location</th><th>Date</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                      {pendingReports.map(r => (
                        <tr key={r.id}>
                          <td className="mono muted">{r.ref_id}</td>
                          <td className="mono" style={{ color: "var(--text-primary)", fontWeight: 500 }}>{r.indicator_value}</td>
                          <td>{getTypeLabel(r.indicator_type)}</td>
                          <td>{r.category}</td>
                          <td>{r.city}{r.state ? `, ${r.state}` : ""}</td>
                          <td className="mono muted">{r.submitted_at?.split("T")[0]}</td>
                          <td>
                            <button className="table-action btn-approve" onClick={() => handleApprove(r.id)}>Approve</button>
                            <button className="table-action btn-reject" onClick={() => handleReject(r.id)}>Reject</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* All Indicators */}
          {adminTab === "indicators" && (
            <div className="table-wrap fade-up-d2">
              <table>
                <thead>
                  <tr><th>ID</th><th>Type</th><th>Value</th><th>Risk</th><th>Reports</th><th>Category</th><th>Last Seen</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {allIndicators.map(ind => {
                    const r = getRiskLevel(ind.risk_score);
                    return (
                      <tr key={ind.id} style={{ cursor: "pointer" }} onClick={() => { setQuery(ind.value); doSearch(ind.value); }}>
                        <td className="mono muted">{ind.ref_id}</td>
                        <td>{getTypeIcon(ind.type)} {getTypeLabel(ind.type)}</td>
                        <td className="mono" style={{ color: "var(--text-primary)", fontWeight: 500, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{ind.value}</td>
                        <td><span className="status-pill" style={{ background: r.bg, color: r.color }}>{ind.risk_score}</span></td>
                        <td className="mono">{ind.complaint_count}</td>
                        <td>{ind.category}</td>
                        <td className="mono muted">{ind.last_seen?.split("T")[0]}</td>
                        <td><span className="status-pill" style={{
                          background: ind.status === "confirmed" ? "rgba(239,68,68,0.15)" : ind.status === "active" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                          color: ind.status === "confirmed" ? "var(--danger)" : ind.status === "active" ? "var(--high-risk)" : "var(--suspicious)",
                          textTransform: "capitalize"
                        }}>{ind.status}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Fraud Trends */}
          {adminTab === "trends" && dashStats && (
            <div className="fade-up-d2">
              <div className="card">
                <div className="card-title">Reports by Scam Category</div>
                <div className="trend-chart">
                  {dashStats.categories.slice(0, 8).map(({ category, count }) => {
                    const max = dashStats.categories[0]?.count || 1;
                    const height = Math.max(10, (count / max) * 120);
                    return (
                      <div key={category} className="trend-bar-group">
                        <div className="trend-count">{count}</div>
                        <div className="trend-bar" style={{ height, background: "linear-gradient(180deg, var(--accent), rgba(255,61,61,0.25))" }} />
                        <div className="trend-label vertical">{category.length > 14 ? category.slice(0, 12) + ".." : category}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="two-col">
                <div className="card">
                  <div className="card-title">Most Reported Indicators</div>
                  {trends?.most_reported?.slice(0, 5).map((ind, i) => (
                    <div key={ind.id} className="rank-item" style={{ borderBottom: i < 4 ? "1px solid var(--border)" : "none" }}>
                      <span className="mono muted" style={{ width: 18 }}>#{i + 1}</span>
                      <span style={{ fontSize: 15 }}>{getTypeIcon(ind.type)}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="mono" style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ind.value}</div>
                      </div>
                      <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--danger)" }}>{ind.complaint_count}</span>
                    </div>
                  ))}
                </div>

                <div className="card">
                  <div className="card-title">Indicator Types Distribution</div>
                  {dashStats.type_distribution.map(({ type, count }) => {
                    const max = dashStats.type_distribution[0]?.count || 1;
                    return (
                      <div key={type} style={{ marginBottom: 12 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{getTypeIcon(type)} {getTypeLabel(type)}</span>
                          <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{count}</span>
                        </div>
                        <div style={{ height: 6, background: "var(--bg-tertiary)", borderRadius: 100, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${(count / max) * 100}%`, background: "var(--accent)", borderRadius: 100 }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─── SCAM PREDICTOR — THE USP ─── */}
      {page === "predictor" && (
        <div style={{ maxWidth: 820, margin: "0 auto", padding: "40px 24px" }}>
          <div className="fade-up" style={{ textAlign: "center", marginBottom: 32 }}>
            <div className="hero-badge" style={{ marginBottom: 16 }}>🔮 India's First Scam Playbook Predictor</div>
            <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8 }}>
              See the scam <span style={{ color: "var(--accent)" }}>before</span> it sees you
            </h2>
            <p style={{ color: "var(--text-secondary)", fontSize: 14, maxWidth: 500, margin: "0 auto" }}>
              Paste any suspicious message — WhatsApp, SMS, email, or call description.
              Our AI reveals the complete scam playbook and shows you exactly what happens next.
            </p>
          </div>

          {/* Input */}
          <div className="card fade-up-d1">
            <div className="card-title">Paste Suspicious Message</div>
            <textarea className="form-textarea" style={{ minHeight: 100, fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}
              placeholder={"Paste the suspicious message here...\n\nExamples:\n• \"Dear customer your SBI KYC has expired. Account will be blocked in 24 hours.\"\n• \"Join our FREE stock tips group! Guaranteed 300% returns!\"\n• \"This is CBI. You are under digital arrest.\""}
              value={predictorMessage}
              onChange={e => setPredictorMessage(e.target.value)} />
            <button className="submit-btn" style={{ marginTop: 12 }}
              onClick={handlePredict}
              disabled={loading || predictorMessage.length < 5}>
              {loading ? "Analyzing..." : "🔍 Analyze Message"}
            </button>
          </div>

          {/* Quick Test Buttons */}
          <div className="fade-up-d1" style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 24 }}>
            {[
              ["KYC Scam", "Dear customer your SBI KYC has expired. Your account will be blocked in 24 hours. Update now: http://sbi-update.in"],
              ["Investment Fraud", "Join our FREE stock tips WhatsApp group! Guaranteed 300% returns! Minimum invest ₹5000"],
              ["Digital Arrest", "This is CBI. You are under digital arrest for money laundering. Stay on video call."],
              ["Job Scam", "Congratulations! Selected for Amazon work from home job. Earn ₹1500 daily. No experience needed."],
              ["OTP Fraud", "This is your bank. We need to verify your account. Please share the OTP sent to your number."],
            ].map(([label, msg]) => (
              <button key={label} className="hint-chip" style={{ fontSize: 11 }}
                onClick={() => { setPredictorMessage(msg); setPrediction(null); }}>
                {label}
              </button>
            ))}
          </div>

          {/* Prediction Result */}
          {prediction && prediction.is_scam && prediction.primary_match && (() => {
            const m = prediction.primary_match;
            const threatColors = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308" };
            const tc = threatColors[m.confidence > 70 ? "CRITICAL" : m.confidence > 40 ? "HIGH" : "MEDIUM"] || "#eab308";
            return (
              <div className="fade-up">
                {/* Alert Banner */}
                <div style={{ padding: 20, borderRadius: 14, background: "rgba(239,68,68,0.08)", border: "1.5px solid rgba(239,68,68,0.3)", marginBottom: 16, display: "flex", alignItems: "center", gap: 14 }}>
                  <span style={{ fontSize: 36 }}>🚨</span>
                  <div>
                    <div style={{ fontSize: 18, fontWeight: 700, color: "#ef4444", marginBottom: 4 }}>SCAM DETECTED</div>
                    <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 2 }}>{m.scam_type}</div>
                    <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>Confidence: {m.confidence}% match with known scam DNA</div>
                  </div>
                </div>

                {/* Quick Stats */}
                <div className="intel-grid" style={{ marginBottom: 16 }}>
                  {[
                    ["Threat Level", prediction.threat_level, tc],
                    ["Victims in India", m.victims_india, "#ef4444"],
                    ["Average Loss", m.avg_loss, "#f97316"],
                    ["Targets", m.targets, null],
                    ["Spread Via", m.common_in?.join(", "), null],
                    ["Confidence", m.confidence + "%", tc],
                  ].map(([label, value, color]) => (
                    <div key={label} className="intel-cell">
                      <div className="intel-cell-label">{label}</div>
                      <div className="intel-cell-value" style={{ fontSize: 12, color: color || "var(--text-primary)" }}>{value}</div>
                    </div>
                  ))}
                </div>

                {/* THE PLAYBOOK — The USP */}
                <div className="card">
                  <div className="card-title">📋 Complete Scam Playbook — What Happens Next</div>
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
                    This is exactly how this scam unfolds step by step. The scammer is following a script — here it is.
                  </p>
                  {m.playbook?.map((step, i) => (
                    <div key={i} style={{ marginBottom: 20, padding: 16, background: "var(--bg-tertiary)", borderRadius: 12, borderLeft: `3px solid ${i === m.playbook.length - 1 ? "#ef4444" : "var(--border-accent)"}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        <span style={{ background: "var(--accent)", color: "white", width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, flexShrink: 0 }}>{step.step}</span>
                        <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>What the scammer says:</span>
                      </div>
                      <div style={{ fontSize: 14, fontStyle: "italic", color: "var(--text-primary)", marginBottom: 10, padding: "8px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8 }}>
                        "{step.scammer_says}"
                      </div>
                      <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
                        <strong style={{ color: "var(--info)" }}>Real purpose:</strong> {step.purpose}
                      </div>
                      <div style={{ fontSize: 13, padding: "6px 10px", background: "rgba(239,68,68,0.08)", borderRadius: 6, color: "#ef4444" }}>
                        🚩 <strong>Red flag:</strong> {step.red_flag}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Money Trail */}
                {m.money_trail && (
                  <div className="card">
                    <div className="card-title">💸 Where Your Money Goes</div>
                    <div style={{ fontSize: 14, lineHeight: 1.8, color: "var(--text-secondary)", padding: 16, background: "var(--bg-tertiary)", borderRadius: 10, fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                      {m.money_trail}
                    </div>
                  </div>
                )}

                {/* Prevention */}
                <div className="card" style={{ borderColor: "rgba(34,197,94,0.3)" }}>
                  <div className="card-title">🛡️ How to Protect Yourself</div>
                  {m.prevention?.map((tip, i) => (
                    <div key={i} style={{ display: "flex", gap: 10, marginBottom: 10, alignItems: "flex-start" }}>
                      <span style={{ color: "var(--safe)", fontSize: 16, flexShrink: 0 }}>✓</span>
                      <span style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.6 }}>{tip}</span>
                    </div>
                  ))}
                </div>

                {/* Share Alert */}
                <div className="action-banner" style={{ borderColor: "var(--info)", background: "rgba(59,130,246,0.06)" }}>
                  <div className="icon">📢</div>
                  <div className="text">
                    <strong>Share this with family & friends</strong>
                    Forward this scam alert to your contacts — especially parents and elderly family members who are most vulnerable to these scams.
                  </div>
                </div>
              </div>
            );
          })()}

          {/* No Scam Detected */}
          {prediction && !prediction.is_scam && (
            <div className="card fade-up" style={{ textAlign: "center", padding: 32 }}>
              <div style={{ fontSize: 36, marginBottom: 12 }}>✅</div>
              <h3 style={{ fontSize: 18, marginBottom: 8 }}>No known scam patterns detected</h3>
              <p style={{ color: "var(--text-secondary)", fontSize: 14 }}>
                This message doesn't match any known scam DNA in our database.
                However, always trust your instincts — if something feels wrong, it probably is.
              </p>
            </div>
          )}

          {/* Scam Library */}
          {scamLibrary.length > 0 && !prediction && (
            <div className="card fade-up-d2">
              <div className="card-title">📚 Scam DNA Library — {scamLibrary.length} Scam Types Mapped</div>
              <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
                Every scam follows a template. We've reverse-engineered {scamLibrary.length} scam playbooks with complete step-by-step breakdowns.
              </p>
              {scamLibrary.map((scam, i) => {
                const colors = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308" };
                return (
                  <div key={scam.id} className="linked-item">
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{scam.name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {scam.targets} · {scam.victims_india} · Avg loss: {scam.avg_loss}
                      </div>
                    </div>
                    <span className="linked-badge" style={{
                      background: `${colors[scam.threat_level] || "#eab308"}20`,
                      color: colors[scam.threat_level] || "#eab308"
                    }}>
                      {scam.threat_level}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {scam.playbook_steps} steps
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ─── LEGAL PAGES ─── */}
      {page === "privacy" && <PrivacyPolicy />}
      {page === "terms" && <TermsOfService />}
      {page === "sources" && <DataSources />}
      {page === "disclaimer" && <Disclaimer />}

      {/* FOOTER */}
      <footer className="footer">
        <div><strong>ScamCheck</strong> — Cybercrime Intelligence Search Engine</div>
        <div style={{ marginTop: 6 }}>
          If you are a victim, report at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a> or call <span className="mono accent">1930</span>
        </div>
        <div className="footer-links">
          <button className="footer-legal-link" onClick={() => { setPage("privacy"); window.scrollTo(0,0); }}>Privacy Policy</button>
          <span style={{ color: "var(--text-muted)" }}>·</span>
          <button className="footer-legal-link" onClick={() => { setPage("terms"); window.scrollTo(0,0); }}>Terms of Service</button>
          <span style={{ color: "var(--text-muted)" }}>·</span>
          <button className="footer-legal-link" onClick={() => { setPage("sources"); window.scrollTo(0,0); }}>Data Sources</button>
          <span style={{ color: "var(--text-muted)" }}>·</span>
          <button className="footer-legal-link" onClick={() => { setPage("disclaimer"); window.scrollTo(0,0); }}>Disclaimer</button>
        </div>
        <div style={{ marginTop: 10, fontSize: 11 }}>
          Not affiliated with any government agency. For informational purposes only.
        </div>
      </footer>

      {/* CONSENT BANNER */}
      {showConsent && (
        <div className="consent-banner">
          <p>
            ScamCheck uses aggregated threat intelligence data to help prevent cybercrime.
            By using this platform, you agree to our <button className="footer-legal-link" style={{ display: "inline", textDecoration: "underline" }} onClick={() => { setPage("terms"); setShowConsent(false); window.scrollTo(0,0); }}>Terms of Service</button> and <button className="footer-legal-link" style={{ display: "inline", textDecoration: "underline" }} onClick={() => { setPage("privacy"); setShowConsent(false); window.scrollTo(0,0); }}>Privacy Policy</button>.
          </p>
          <button className="consent-btn" onClick={() => setShowConsent(false)}>I Understand</button>
        </div>
      )}
    </div>
  );
}
