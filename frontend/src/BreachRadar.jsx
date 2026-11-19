import React, { useState, useEffect, useMemo } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "https://scamcheck-api-india.onrender.com";

/* ─── helpers ───────────────────────────────────────────────────── */
function timeAgo(dateStr) {
  if (!dateStr) return "";
  try {
    const d = new Date(dateStr.replace(" ", "T"));
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return d.toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
  } catch { return dateStr; }
}

function formatCount(n) {
  if (!n) return "0";
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function stripHtml(html) {
  if (!html) return "";
  return html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

/* ─── mini bar chart (pure CSS) ─────────────────────────────────── */
function MiniBar({ data }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div>
      {data.map((d, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: 11, minWidth: 120, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.label}</span>
          <div style={{ flex: 1, background: "var(--bg-tertiary)", borderRadius: 3, height: 14, overflow: "hidden" }}>
            <div style={{ width: `${(d.count / max) * 100}%`, height: "100%", background: d.color || "var(--accent)", borderRadius: 3, transition: "width 0.3s" }} />
          </div>
          <span className="mono" style={{ fontSize: 11, minWidth: 30, textAlign: "right", color: "var(--text-muted)" }}>{d.count}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── tweet builders (Krebs/Cluley voice) ──────────────────────── */
function buildBreachTweet(breach) {
  const name = breach.title || breach.name || "Unknown";
  const domain = breach.domain || "";
  const count = breach.pwn_count || 0;
  const countStr = formatCount(count);
  const dateStr = breach.breach_date || "";
  const dataTypes = (breach.data_classes || []).slice(0, 3).join(", ");

  const templates = [
    `The ${name} data breach${domain ? ` (${domain})` : ""} exposed ${countStr} records.${dataTypes ? ` Compromised data includes ${dataTypes}.` : ""}${dateStr ? ` The breach occurred in ${dateStr}.` : ""} Check your exposure at https://cyberintelengine.com`,
    `${countStr} accounts were compromised in the ${name} breach.${domain ? ` The affected service is ${domain}.` : ""}${dataTypes ? ` Exposed data types: ${dataTypes}.` : ""} If you used this service, change your passwords now. https://cyberintelengine.com`,
    `${name} breach: ${countStr} records exposed${dateStr ? `, dating back to ${dateStr}` : ""}.${dataTypes ? ` The leaked data includes ${dataTypes}.` : ""} Users of ${domain || "the affected service"} should review their account security. https://cyberintelengine.com`,
    `A breach at ${domain || name} has exposed ${countStr} user records to the public.${dataTypes ? ` The dataset includes ${dataTypes}.` : ""} Anyone who has used this service should assume their data is compromised. https://cyberintelengine.com`,
  ];

  return templates[Math.floor(Math.random() * templates.length)];
}

function buildStatsTweet(stats) {
  const total = stats.total_breaches || 0;
  const records = stats.total_records_formatted || "0";
  const recent = stats.recent_90d || 0;
  const topBreach = stats.largest_breaches?.[0];

  const templates = [
    `CyberIntelEngine now tracks ${total} known data breaches, exposing a combined ${records} records. ${recent} new breaches were added in the last 90 days.${topBreach ? ` The largest on record is ${topBreach.name} with ${topBreach.pwn_count_formatted} accounts.` : ""} https://cyberintelengine.com`,
    `${total} data breaches. ${records} compromised records. ${recent} breaches added in the past three months alone. The scale of exposed personal data continues to grow. Search your exposure at https://cyberintelengine.com`,
    `The breach landscape in numbers: ${total} known breaches tracked, ${records} total records exposed, ${recent} added in the last 90 days.${topBreach ? ` ${topBreach.name} remains the largest single breach at ${topBreach.pwn_count_formatted} records.` : ""} https://cyberintelengine.com`,
  ];

  return templates[Math.floor(Math.random() * templates.length)];
}


/* ═══════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════════════════ */
export function BreachRadar() {
  const [stats, setStats] = useState(null);
  const [catalog, setCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("overview");
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [catalogLimit, setCatalogLimit] = useState(50);
  const [expandedCard, setExpandedCard] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [catalogSearch, setCatalogSearch] = useState("");
  const [verifiedFilter, setVerifiedFilter] = useState(false);

  /* ── copy helper ── */
  const copyTweet = (text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIndex(key);
      setTimeout(() => setCopiedIndex(null), 2000);
    });
  };

  /* ── load data ── */
  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE}/breaches/stats`).then(r => r.json()),
      fetch(`${API_BASE}/breaches/catalog?limit=500`).then(r => r.json()),
    ])
      .then(([statsData, catalogData]) => {
        setStats(statsData);
        setCatalog(Array.isArray(catalogData) ? catalogData : []);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  /* ── search handler ── */
  const doSearch = () => {
    if (!searchQuery.trim()) return;
    setSearchLoading(true);
    setSearchResults(null);
    fetch(`${API_BASE}/breaches/search/${encodeURIComponent(searchQuery.trim())}`)
      .then(r => r.json())
      .then(data => setSearchResults(Array.isArray(data) ? data : []))
      .catch(() => setSearchResults([]))
      .finally(() => setSearchLoading(false));
  };

  /* ── filtered catalog ── */
  const filteredCatalog = useMemo(() => {
    let result = catalog;
    if (verifiedFilter) {
      result = result.filter(b => b.is_verified);
    }
    if (catalogSearch) {
      const q = catalogSearch.toLowerCase();
      result = result.filter(b =>
        (b.name || "").toLowerCase().includes(q) ||
        (b.title || "").toLowerCase().includes(q) ||
        (b.domain || "").toLowerCase().includes(q) ||
        (b.industry || "").toLowerCase().includes(q)
      );
    }
    return result;
  }, [catalog, verifiedFilter, catalogSearch]);

  /* ── risk badge style ── */
  const riskBadge = (count) => {
    if (count >= 100_000_000) return { bg: "rgba(255,61,61,0.12)", color: "#ff3d3d", border: "rgba(255,61,61,0.25)", label: "Critical" };
    if (count >= 10_000_000) return { bg: "rgba(255,140,0,0.12)", color: "#ff8c00", border: "rgba(255,140,0,0.25)", label: "Severe" };
    if (count >= 1_000_000) return { bg: "rgba(234,179,8,0.12)", color: "#eab308", border: "rgba(234,179,8,0.25)", label: "Major" };
    return { bg: "var(--bg-tertiary)", color: "var(--text-muted)", border: "var(--border)", label: "Notable" };
  };

  if (loading) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div style={{ textAlign: "center", padding: 80 }}>
          <div className="pulse" style={{ fontSize: 48, marginBottom: 16 }}>&#x1F6E1;</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Loading Breach Intelligence...</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Aggregating from HaveIBeenPwned and XposedOrNot</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div className="card" style={{ textAlign: "center", padding: 40, borderColor: "var(--accent)" }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>&#x26A0;</div>
          <div style={{ color: "var(--accent)", fontWeight: 600, marginBottom: 8 }}>Unable to load breach data</div>
          <div style={{ color: "var(--text-muted)", fontSize: 13 }}>{error}</div>
          <button onClick={() => window.location.reload()} className="cta-btn" style={{ marginTop: 16, padding: "8px 24px", fontSize: 13 }}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 24, fontWeight: 800, letterSpacing: -0.5, marginBottom: 4 }}>
          Breach Radar
        </h2>
        <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Global data breach intelligence aggregated from HaveIBeenPwned and XposedOrNot
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 20, overflowX: "auto", paddingBottom: 4 }}>
        {[
          ["overview", "Overview"],
          ["browse", "Browse Breaches"],
          ["search", "Search"],
          ["analytics", "Analytics"],
        ].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)}
            style={{
              padding: "8px 18px", borderRadius: 8, fontSize: 13, fontWeight: 600,
              border: "1px solid var(--border)", cursor: "pointer", whiteSpace: "nowrap",
              background: tab === key ? "var(--accent)" : "var(--bg-secondary)",
              color: tab === key ? "white" : "var(--text-secondary)",
              transition: "all 0.15s",
            }}>
            {label}
          </button>
        ))}
      </div>

      {/* ═══ TAB: Overview ════════════════════════════════════════════ */}
      {tab === "overview" && stats && (
        <div>
          {/* Stats cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10, marginBottom: 20 }}>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--accent)" }}>{stats.total_breaches}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Known Breaches</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#ff8c00" }}>{stats.total_records_formatted}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Records Exposed</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--info)" }}>{stats.verified_count}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Verified</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#51cf66" }}>{stats.recent_90d}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Added (90d)</div>
            </div>
          </div>

          {/* Share Stats Tweet */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <button onClick={() => copyTweet(buildStatsTweet(stats), "stats")}
              style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: `1px solid ${copiedIndex === "stats" ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === "stats" ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === "stats" ? "#51cf66" : "var(--text-secondary)", cursor: "pointer" }}>
              {copiedIndex === "stats" ? "Copied!" : "Copy Stats Tweet"}
            </button>
          </div>

          {/* Largest breaches */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">Largest Known Breaches</div>
            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 500 }}>
                  <thead>
                    <tr style={{ background: "var(--bg-tertiary)" }}>
                      <th style={thStyle}>#</th>
                      <th style={thStyle}>Breach</th>
                      <th style={thStyle}>Domain</th>
                      <th style={thStyle}>Records</th>
                      <th style={thStyle}>Date</th>
                      <th style={thStyle}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {(stats.largest_breaches || []).map((b, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{i + 1}</span></td>
                        <td style={tdStyle}><span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{b.name}</span></td>
                        <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--info)" }}>{b.domain || ""}</span></td>
                        <td style={tdStyle}><span className="mono" style={{ fontWeight: 700, color: "var(--accent)" }}>{b.pwn_count_formatted}</span></td>
                        <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{b.breach_date || ""}</span></td>
                        <td style={tdStyle}>
                          <button onClick={() => { const full = catalog.find(c => c.name?.toLowerCase() === b.name?.toLowerCase() || c.title?.toLowerCase() === b.name?.toLowerCase()); if (full) copyTweet(buildBreachTweet(full), `largest-${i}`); }}
                            style={{ padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `largest-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `largest-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `largest-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap" }}>
                            {copiedIndex === `largest-${i}` ? "Copied" : "Tweet"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Recent breaches */}
          {stats.recent_breaches && stats.recent_breaches.length > 0 && (
            <div className="card">
              <div className="card-title">Recently Added Breaches (Last 90 Days)</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {stats.recent_breaches.slice(0, 10).map((b, i) => {
                  const badge = riskBadge(b.pwn_count || 0);
                  return (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 12px", background: "var(--bg-tertiary)", borderRadius: 8, gap: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                          <span style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>{b.title || b.name}</span>
                          {b.is_verified && (
                            <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(81,207,102,0.12)", color: "#51cf66", border: "1px solid rgba(81,207,102,0.25)" }}>Verified</span>
                          )}
                          <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: badge.bg, color: badge.color, border: `1px solid ${badge.border}` }}>{formatCount(b.pwn_count)} records</span>
                        </div>
                        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                          {b.domain ? `${b.domain} / ` : ""}{b.breach_date ? `Breached ${b.breach_date}` : ""}{b.added_date ? ` / Added ${timeAgo(b.added_date)}` : ""}
                        </div>
                      </div>
                      <button onClick={() => copyTweet(buildBreachTweet(b), `recent-${i}`)}
                        style={{ padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `recent-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `recent-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `recent-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0 }}>
                        {copiedIndex === `recent-${i}` ? "Copied" : "Tweet"}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Browse Breaches ═════════════════════════════════════ */}
      {tab === "browse" && (
        <div>
          {/* Filters */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
            <input type="text" placeholder="Filter by name, domain, or industry..."
              value={catalogSearch} onChange={e => { setCatalogSearch(e.target.value); setCatalogLimit(50); setExpandedCard(null); }}
              style={{ flex: 1, minWidth: 200, padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 12 }}
            />
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)", cursor: "pointer" }}>
              <input type="checkbox" checked={verifiedFilter} onChange={e => { setVerifiedFilter(e.target.checked); setCatalogLimit(50); setExpandedCard(null); }} />
              Verified only
            </label>
          </div>

          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10 }}>
            Showing {Math.min(filteredCatalog.length, catalogLimit)} of {filteredCatalog.length} breaches
          </div>

          {/* Breach cards */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {filteredCatalog.slice(0, catalogLimit).map((b, i) => {
              const isExpanded = expandedCard === i;
              const badge = riskBadge(b.pwn_count || 0);
              const descText = stripHtml(b.description);

              return (
                <div key={i} className="card" style={{
                  padding: 0, transition: "border-color 0.2s",
                  borderColor: isExpanded ? "var(--info)" : undefined,
                }}
                  onMouseOver={e => { if (!isExpanded) e.currentTarget.style.borderColor = "rgba(59,130,246,0.4)"; }}
                  onMouseOut={e => { if (!isExpanded) e.currentTarget.style.borderColor = "var(--border)"; }}>

                  {/* Card header */}
                  <div style={{ padding: 14, cursor: "pointer" }} onClick={() => setExpandedCard(isExpanded ? null : i)}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                          <span style={{ padding: "3px 10px", borderRadius: 5, fontSize: 11, fontWeight: 700, background: badge.bg, color: badge.color, border: `1px solid ${badge.border}` }}>
                            {formatCount(b.pwn_count)} records
                          </span>
                          {b.is_verified && (
                            <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(81,207,102,0.12)", color: "#51cf66", border: "1px solid rgba(81,207,102,0.25)" }}>Verified</span>
                          )}
                          {b.is_sensitive && (
                            <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(255,61,61,0.12)", color: "#ff3d3d", border: "1px solid rgba(255,61,61,0.25)" }}>Sensitive</span>
                          )}
                          {b.is_stealer_log && (
                            <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(255,140,0,0.12)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.25)" }}>Stealer Log</span>
                          )}
                          {b.is_malware && (
                            <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(255,140,0,0.12)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.25)" }}>Malware</span>
                          )}
                          <span className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>{b.breach_date || ""}</span>
                        </div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
                          {b.title || b.name}
                        </div>
                        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12, alignItems: "center" }}>
                          {b.domain && <span className="mono" style={{ color: "var(--info)" }}>{b.domain}</span>}
                          {b.industry && <span style={{ color: "var(--text-secondary)" }}>{b.industry}</span>}
                          <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>{isExpanded ? "Less" : "Details"}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div style={{ borderTop: "1px solid var(--border)", background: "var(--bg-tertiary)", padding: 16 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 14 }}>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Breach Date</div>
                          <div className="mono" style={{ fontSize: 13, color: "var(--text-primary)" }}>{b.breach_date || "Unknown"}</div>
                        </div>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Added to Database</div>
                          <div className="mono" style={{ fontSize: 13, color: "var(--text-primary)" }}>{b.added_date ? timeAgo(b.added_date) : "Unknown"}</div>
                        </div>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Records Exposed</div>
                          <div className="mono" style={{ fontSize: 13, color: "var(--accent)", fontWeight: 700 }}>{(b.pwn_count || 0).toLocaleString()}</div>
                        </div>
                        {b.industry && (
                          <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                            <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Industry</div>
                            <div style={{ fontSize: 13, color: "var(--text-primary)" }}>{b.industry}</div>
                          </div>
                        )}
                        {b.password_risk && (
                          <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                            <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Password Risk</div>
                            <div style={{ fontSize: 13, color: b.password_risk === "plaintext" ? "#ff3d3d" : b.password_risk === "unknown" ? "#ff8c00" : "var(--text-primary)", fontWeight: 600 }}>{b.password_risk}</div>
                          </div>
                        )}
                      </div>

                      {/* Data classes */}
                      {b.data_classes && b.data_classes.length > 0 && (
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)", marginBottom: 12 }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>Compromised Data Types</div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            {b.data_classes.map((dc, j) => (
                              <span key={j} style={{ padding: "3px 10px", borderRadius: 20, fontSize: 11, background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border)" }}>
                                {dc}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Description */}
                      {descText && (
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)", marginBottom: 12 }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Description</div>
                          <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>{descText}</div>
                        </div>
                      )}

                      {/* Action buttons */}
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <button onClick={(e) => { e.stopPropagation(); copyTweet(buildBreachTweet(b), `browse-${i}`); }}
                          style={{
                            padding: "8px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600,
                            border: `1px solid ${copiedIndex === `browse-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`,
                            background: copiedIndex === `browse-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)",
                            color: copiedIndex === `browse-${i}` ? "#51cf66" : "var(--text-secondary)",
                            cursor: "pointer",
                          }}>
                          {copiedIndex === `browse-${i}` ? "Copied!" : "Copy Tweet"}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {filteredCatalog.length > catalogLimit && (
            <div style={{ textAlign: "center", marginTop: 16 }}>
              <button onClick={() => setCatalogLimit(prev => prev + 50)} className="cta-btn" style={{ padding: "10px 24px", fontSize: 13 }}>
                Load More ({filteredCatalog.length - catalogLimit} remaining)
              </button>
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Search ══════════════════════════════════════════════ */}
      {tab === "search" && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title">Search Breach Intelligence</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12 }}>
              Search by company name, domain, data type, or industry
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input type="text" placeholder="Enter domain, company, or keyword..."
                value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                onKeyDown={e => e.key === "Enter" && doSearch()}
                style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14 }}
              />
              <button onClick={doSearch} className="cta-btn" disabled={searchLoading} style={{ padding: "10px 20px", fontSize: 14 }}>
                {searchLoading ? "Searching..." : "Search"}
              </button>
            </div>
          </div>

          {searchResults !== null && (
            <div>
              {searchResults.length === 0 ? (
                <div className="card" style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No breaches found for "{searchQuery}"
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10 }}>
                    Found {searchResults.length} breaches matching "{searchQuery}"
                  </div>
                  <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 600 }}>
                        <thead>
                          <tr style={{ background: "var(--bg-tertiary)" }}>
                            <th style={thStyle}>Breach</th>
                            <th style={thStyle}>Domain</th>
                            <th style={thStyle}>Records</th>
                            <th style={thStyle}>Date</th>
                            <th style={thStyle}>Status</th>
                            <th style={thStyle}></th>
                          </tr>
                        </thead>
                        <tbody>
                          {searchResults.map((b, i) => (
                            <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                              <td style={tdStyle}><span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{b.title || b.name}</span></td>
                              <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--info)" }}>{b.domain || ""}</span></td>
                              <td style={tdStyle}><span className="mono" style={{ fontWeight: 700, color: "var(--accent)" }}>{formatCount(b.pwn_count)}</span></td>
                              <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{b.breach_date || ""}</span></td>
                              <td style={tdStyle}>
                                {b.is_verified ? <span style={{ fontSize: 10, color: "#51cf66", fontWeight: 600 }}>Verified</span> : <span style={{ fontSize: 10, color: "var(--text-muted)" }}>Unverified</span>}
                              </td>
                              <td style={tdStyle}>
                                <button onClick={() => copyTweet(buildBreachTweet(b), `search-${i}`)}
                                  style={{ padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `search-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `search-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `search-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap" }}>
                                  {copiedIndex === `search-${i}` ? "Copied" : "Tweet"}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Analytics ═══════════════════════════════════════════ */}
      {tab === "analytics" && stats && (
        <div>
          {/* Share analytics tweet */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <button onClick={() => copyTweet(buildStatsTweet(stats), "analytics-tweet")}
              style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: `1px solid ${copiedIndex === "analytics-tweet" ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === "analytics-tweet" ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === "analytics-tweet" ? "#51cf66" : "var(--text-secondary)", cursor: "pointer" }}>
              {copiedIndex === "analytics-tweet" ? "Copied!" : "Copy Stats Tweet"}
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div className="card">
              <div className="card-title">Most Commonly Exposed Data Types</div>
              <MiniBar data={(stats.top_data_classes || []).map(dc => ({
                label: dc.name,
                count: dc.count,
                color: "var(--accent)",
              }))} />
            </div>
            <div className="card">
              <div className="card-title">Breaches by Year</div>
              <MiniBar data={(stats.yearly_breakdown || []).map(y => ({
                label: y.year,
                count: y.count,
                color: "var(--info)",
              }))} />
            </div>
          </div>

          {stats.top_industries && stats.top_industries.length > 0 && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Most Breached Industries</div>
              <MiniBar data={stats.top_industries.map(ind => ({
                label: ind.industry,
                count: ind.count,
                color: "#ff8c00",
              }))} />
            </div>
          )}

          <div className="card">
            <div className="card-title">Largest Breaches by Record Count</div>
            <MiniBar data={(stats.largest_breaches || []).map(b => ({
              label: b.name,
              count: b.pwn_count,
              color: "var(--accent)",
            }))} />
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "24px 0", marginTop: 32, borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.8 }}>
        Breach data aggregated from HaveIBeenPwned and XposedOrNot
        {" / "}Updated hourly
        <br />
        CyberIntelEngine does not store or process personal breach data
      </div>
    </div>
  );
}

/* ─── table styles ──────────────────────────────────────────────── */
const thStyle = {
  textAlign: "left", padding: "10px 12px", fontSize: 11,
  color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6,
  fontWeight: 600, borderBottom: "1px solid var(--border)", whiteSpace: "nowrap",
};
const tdStyle = { padding: "10px 12px", verticalAlign: "top" };
