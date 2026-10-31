import React, { useState, useEffect, useMemo } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "https://scamcheck-api-india.onrender.com";

/* ─── helpers ───────────────────────────────────────────────────── */
function timeAgo(dateStr) {
  if (!dateStr) return "—";
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

function countryFlag(code) {
  if (!code || code.length !== 2) return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
}

/* ─── mini bar chart (pure CSS) ─────────────────────────────────── */
function MiniBar({ data, maxWidth = "100%" }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div style={{ width: maxWidth }}>
      {data.map((d, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <div className="mono" style={{ fontSize: 11, width: 130, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>
            {d.label}
          </div>
          <div style={{ flex: 1, height: 18, background: "var(--bg-tertiary)", borderRadius: 4, overflow: "hidden" }}>
            <div style={{
              width: `${(d.count / max) * 100}%`, height: "100%",
              background: d.color || "var(--accent)", borderRadius: 4,
              transition: "width 0.6s ease",
            }} />
          </div>
          <div className="mono" style={{ fontSize: 11, width: 36, textAlign: "right", color: "var(--text-muted)" }}>
            {d.count}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── timeline sparkline (SVG) ──────────────────────────────────── */
function Sparkline({ data, width = 420, height = 80 }) {
  if (!data || data.length === 0) return <div style={{ color: "var(--text-muted)", fontSize: 12 }}>No timeline data</div>;
  const max = Math.max(...data.map(d => d.count), 1);
  const step = width / Math.max(data.length - 1, 1);
  const points = data.map((d, i) => `${i * step},${height - (d.count / max) * (height - 10)}`).join(" ");
  const area = `0,${height} ${points} ${(data.length - 1) * step},${height}`;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: height, display: "block" }}>
      <defs>
        <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={area} fill="url(#sparkGrad)" />
      <polyline points={points} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

/* ═══ main component ════════════════════════════════════════════════ */
export function RansomwareTracker() {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("feed");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [groupVictims, setGroupVictims] = useState(null);
  const [groupLoading, setGroupLoading] = useState(false);
  const [feedFilter, setFeedFilter] = useState("");
  const [selectedCountry, setSelectedCountry] = useState(null);
  const [countryVictims, setCountryVictims] = useState(null);
  const [countryLoading, setCountryLoading] = useState(false);
  const [countrySearch, setCountrySearch] = useState("");

  /* ── load dashboard ── */
  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/ransomware/dashboard`)
      .then(r => r.json())
      .then(data => {
        if (data.error) throw new Error(data.message || "API error");
        setDashboard(data);
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
    fetch(`${API_BASE}/ransomware/victims/search/${encodeURIComponent(searchQuery.trim())}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) throw new Error(data.message);
        setSearchResults(Array.isArray(data) ? data : []);
      })
      .catch(() => setSearchResults([]))
      .finally(() => setSearchLoading(false));
  };

  /* ── group detail handler ── */
  const loadGroupVictims = (groupName) => {
    setSelectedGroup(groupName);
    setGroupLoading(true);
    setGroupVictims(null);
    fetch(`${API_BASE}/ransomware/group/${encodeURIComponent(groupName)}/victims`)
      .then(r => r.json())
      .then(data => setGroupVictims(Array.isArray(data) ? data : []))
      .catch(() => setGroupVictims([]))
      .finally(() => setGroupLoading(false));
  };

  /* ── country drill-down handler ── */
  const loadCountryVictims = (countryCode) => {
    setSelectedCountry(countryCode);
    setCountryLoading(true);
    setCountryVictims(null);
    fetch(`${API_BASE}/ransomware/victims/country/${countryCode}`)
      .then(r => r.json())
      .then(data => setCountryVictims(Array.isArray(data) ? data : []))
      .catch(() => setCountryVictims([]))
      .finally(() => setCountryLoading(false));
  };

  /* ── filtered feed ── */
  const filteredVictims = useMemo(() => {
    if (!dashboard?.recent_victims) return [];
    if (!feedFilter) return dashboard.recent_victims;
    const q = feedFilter.toLowerCase();
    return dashboard.recent_victims.filter(v =>
      (v.victim || "").toLowerCase().includes(q) ||
      (v.group_name || "").toLowerCase().includes(q) ||
      (v.country || "").toLowerCase().includes(q) ||
      (v.country_name || "").toLowerCase().includes(q) ||
      (v.activity || "").toLowerCase().includes(q)
    );
  }, [dashboard, feedFilter]);

  /* ── filtered countries ── */
  const filteredCountries = useMemo(() => {
    if (!dashboard?.all_countries) return [];
    if (!countrySearch) return dashboard.all_countries;
    const q = countrySearch.toLowerCase();
    return dashboard.all_countries.filter(c =>
      (c.name || "").toLowerCase().includes(q) ||
      (c.code || "").toLowerCase().includes(q)
    );
  }, [dashboard, countrySearch]);

  /* ═══ render ══════════════════════════════════════════════════════ */

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 80 }}>
        <div className="pulse" style={{ fontSize: 48, marginBottom: 16 }}>🔴</div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Loading Global Ransomware Intelligence...</div>
        <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 8 }}>Pulling live data from ransomware.live API</div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ textAlign: "center", padding: 80 }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>⚠️</div>
        <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>Connection Issue</div>
        <div style={{ fontSize: 14, color: "var(--text-secondary)", maxWidth: 400, margin: "0 auto", lineHeight: 1.7 }}>
          Could not reach the ransomware intelligence API. This may be due to rate limiting or a temporary outage.
        </div>
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 12 }}>{error}</div>
        <button onClick={() => window.location.reload()} className="cta-btn" style={{ marginTop: 20 }}>Retry</button>
      </div>
    );
  }

  const stats = dashboard?.stats || {};

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto" }}>

      {/* ── Hero ── */}
      <div style={{ textAlign: "center", marginBottom: 32 }}>
        <div className="hero-badge" style={{ marginBottom: 12 }}>
          <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: "#ff3d3d", marginRight: 8, animation: "pulse 2s infinite" }} />
          LIVE GLOBAL RANSOMWARE INTELLIGENCE
        </div>
        <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: -1, marginBottom: 8 }}>
          Global Ransomware <span style={{ color: "var(--accent)" }}>Threat Tracker</span>
        </h2>
        <p style={{ color: "var(--text-secondary)", fontSize: 14, maxWidth: 600, margin: "0 auto" }}>
          Real-time ransomware group activity, victim claims, and threat intelligence across all countries — powered by ransomware.live
        </p>
      </div>

      {/* ── Stat cards ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginBottom: 24 }}>
        {[
          [stats.total_recent_victims || 0, "Global Victims", "var(--accent)"],
          [stats.total_groups || 0, "Active Groups", "var(--high-risk)"],
          [stats.total_countries_hit || 0, "Countries Hit", "var(--warning)"],
          [stats.top_group || "—", "Most Active Group", "var(--info)"],
          [stats.top_country ? `${countryFlag(stats.top_country_code)} ${stats.top_country}` : "—", "Most Targeted", "var(--safe)"],
        ].map(([num, label, color]) => (
          <div key={label} className="card" style={{ textAlign: "center", padding: 16 }}>
            <div className="mono" style={{ fontSize: 20, fontWeight: 700, color }}>{num}</div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          ["feed", "🔴 Live Feed"],
          ["countries", "🌍 Countries"],
          ["groups", "👥 Groups"],
          ["analytics", "📊 Analytics"],
          ["search", "🔍 Search"],
        ].map(([key, label]) => (
          <button key={key} onClick={() => { setTab(key); setSelectedGroup(null); setSelectedCountry(null); }}
            style={{
              padding: "8px 16px", borderRadius: 8, border: "1px solid var(--border)",
              background: tab === key ? "var(--accent)" : "var(--bg-secondary)",
              color: tab === key ? "white" : "var(--text-secondary)",
              cursor: "pointer", fontSize: 13, fontWeight: 600, transition: "all 0.2s",
            }}>
            {label}
          </button>
        ))}
      </div>

      {/* ═══ TAB: Live Feed ════════════════════════════════════════ */}
      {tab === "feed" && (
        <div>
          <div style={{ marginBottom: 16, display: "flex", gap: 8, alignItems: "center" }}>
            <input type="text" placeholder="Filter by victim, group, country, sector..."
              value={feedFilter} onChange={e => setFeedFilter(e.target.value)}
              style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 13 }}
            />
            {feedFilter && (
              <button onClick={() => setFeedFilter("")} style={{ padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-tertiary)", color: "var(--text-muted)", cursor: "pointer", fontSize: 12 }}>Clear</button>
            )}
          </div>

          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 12, display: "flex", justifyContent: "space-between" }}>
            <span>Showing {filteredVictims.length} claims worldwide</span>
            <span>Updated: {dashboard?.last_updated ? new Date(dashboard.last_updated).toLocaleString("en-IN") : "—"}</span>
          </div>

          <div className="card" style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 600 }}>
                <thead>
                  <tr style={{ background: "var(--bg-tertiary)" }}>
                    <th style={thStyle}>When</th>
                    <th style={thStyle}>Group</th>
                    <th style={thStyle}>Victim</th>
                    <th style={thStyle}>Country</th>
                    <th style={thStyle}>Sector</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredVictims.slice(0, 100).map((v, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}
                      onMouseOver={e => e.currentTarget.style.background = "var(--bg-tertiary)"}
                      onMouseOut={e => e.currentTarget.style.background = "transparent"}>
                      <td style={tdStyle}>
                        <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{timeAgo(v.discovered)}</span>
                      </td>
                      <td style={tdStyle}>
                        <span onClick={() => { setTab("groups"); loadGroupVictims(v.group_name); }}
                          style={{ color: "var(--accent)", cursor: "pointer", fontWeight: 600, fontSize: 12 }}>
                          {v.group_name}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <div style={{ fontWeight: 500 }}>{v.victim}</div>
                        {v.website && (
                          <div style={{ fontSize: 11, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }}>
                            {v.website}
                          </div>
                        )}
                      </td>
                      <td style={tdStyle}>
                        {v.country ? (
                          <span onClick={() => { setTab("countries"); loadCountryVictims(v.country); }}
                            style={{ cursor: "pointer", color: "var(--info)" }}>
                            {countryFlag(v.country)} {v.country_name || v.country}
                          </span>
                        ) : "—"}
                      </td>
                      <td style={tdStyle}>
                        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>{v.activity || "—"}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══ TAB: Countries (GLOBAL) ═══════════════════════════════ */}
      {tab === "countries" && (
        <div>
          {selectedCountry ? (
            /* ── Country drill-down ── */
            <div>
              <button onClick={() => { setSelectedCountry(null); setCountryVictims(null); }}
                style={{ padding: "6px 14px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-secondary)", cursor: "pointer", fontSize: 12, marginBottom: 16 }}>
                ← Back to All Countries
              </button>
              <div className="card" style={{ marginBottom: 16, borderColor: "rgba(59,130,246,0.3)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ fontSize: 36 }}>{countryFlag(selectedCountry)}</span>
                  <div>
                    <div className="card-title" style={{ color: "var(--info)", marginBottom: 2 }}>
                      {dashboard?.all_countries?.find(c => c.code === selectedCountry)?.name || selectedCountry}
                    </div>
                    <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                      {countryLoading ? "Loading victims..." : `${countryVictims?.length || 0} ransomware victims recorded`}
                    </div>
                  </div>
                </div>
              </div>
              {!countryLoading && countryVictims && (
                countryVictims.length === 0 ? (
                  <div className="card" style={{ textAlign: "center", padding: 40 }}>
                    <div style={{ fontSize: 36, marginBottom: 12 }}>🛡️</div>
                    <div style={{ color: "var(--text-muted)" }}>No ransomware victims recorded for this country in the current dataset.</div>
                  </div>
                ) : (
                  <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 500 }}>
                        <thead>
                          <tr style={{ background: "var(--bg-tertiary)" }}>
                            <th style={thStyle}>When</th>
                            <th style={thStyle}>Group</th>
                            <th style={thStyle}>Victim</th>
                            <th style={thStyle}>Sector</th>
                          </tr>
                        </thead>
                        <tbody>
                          {countryVictims.slice(0, 200).map((v, i) => (
                            <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                              <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{timeAgo(v.discovered)}</span></td>
                              <td style={tdStyle}>
                                <span onClick={() => { setTab("groups"); loadGroupVictims(v.group_name); }}
                                  style={{ color: "var(--accent)", cursor: "pointer", fontWeight: 600, fontSize: 12 }}>{v.group_name}</span>
                              </td>
                              <td style={tdStyle}>{v.victim}</td>
                              <td style={tdStyle}><span style={{ fontSize: 11 }}>{v.activity || "—"}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )
              )}
            </div>
          ) : (
            /* ── Global country list ── */
            <div>
              <div className="action-banner" style={{ borderColor: "var(--info)", background: "rgba(59,130,246,0.06)", marginBottom: 20 }}>
                <div className="icon">🌍</div>
                <div className="text">
                  <strong>Global Ransomware Impact</strong>
                  {stats.total_countries_hit || 0} countries affected. Click any country to see its victims.
                </div>
              </div>

              <input type="text" placeholder="Search countries..."
                value={countrySearch} onChange={e => setCountrySearch(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 13, marginBottom: 16, boxSizing: "border-box" }}
              />

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
                {filteredCountries.map((c, i) => (
                  <div key={c.code} className="card" onClick={() => loadCountryVictims(c.code)}
                    style={{ cursor: "pointer", padding: 14, transition: "border-color 0.2s", display: "flex", alignItems: "center", gap: 12 }}
                    onMouseOver={e => e.currentTarget.style.borderColor = "var(--info)"}
                    onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                    <span style={{ fontSize: 28 }}>{countryFlag(c.code)}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{c.code}</div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: c.count > 10 ? "var(--accent)" : c.count > 3 ? "var(--warning)" : "var(--text-secondary)" }}>{c.count}</div>
                      <div style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase" }}>victims</div>
                    </div>
                  </div>
                ))}
              </div>

              {filteredCountries.length === 0 && (
                <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No countries match "{countrySearch}"
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Groups ══════════════════════════════════════════ */}
      {tab === "groups" && (
        <div>
          {selectedGroup ? (
            <div>
              <button onClick={() => { setSelectedGroup(null); setGroupVictims(null); }}
                style={{ padding: "6px 14px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-secondary)", cursor: "pointer", fontSize: 12, marginBottom: 16 }}>
                ← Back to Groups
              </button>
              <div className="card" style={{ marginBottom: 16, borderColor: "rgba(255,61,61,0.3)" }}>
                <div className="card-title" style={{ color: "var(--accent)" }}>{selectedGroup}</div>
                <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  {groupLoading ? "Loading victims..." : `${groupVictims?.length || 0} total victims claimed worldwide`}
                </div>
              </div>
              {!groupLoading && groupVictims && (
                <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 500 }}>
                      <thead>
                        <tr style={{ background: "var(--bg-tertiary)" }}>
                          <th style={thStyle}>When</th>
                          <th style={thStyle}>Victim</th>
                          <th style={thStyle}>Country</th>
                          <th style={thStyle}>Sector</th>
                        </tr>
                      </thead>
                      <tbody>
                        {groupVictims.slice(0, 200).map((v, i) => (
                          <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                            <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{timeAgo(v.discovered)}</span></td>
                            <td style={tdStyle}>{v.victim}</td>
                            <td style={tdStyle}>
                              {v.country ? (
                                <span onClick={() => { setTab("countries"); loadCountryVictims(v.country); }}
                                  style={{ cursor: "pointer", color: "var(--info)" }}>
                                  {countryFlag(v.country)} {v.country_name || v.country}
                                </span>
                              ) : "—"}
                            </td>
                            <td style={tdStyle}><span style={{ fontSize: 11 }}>{v.activity || "—"}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div>
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-title">Top Active Ransomware Groups (Worldwide)</div>
                <MiniBar data={(dashboard?.top_groups || []).map(g => ({ label: g.name, count: g.count, color: "var(--accent)" }))} />
              </div>
              <div className="card-title" style={{ marginBottom: 12 }}>All Groups Directory</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
                {(dashboard?.groups_directory || []).map((g, i) => (
                  <div key={i} className="card" onClick={() => loadGroupVictims(g.name)}
                    style={{ cursor: "pointer", padding: 14, transition: "border-color 0.2s" }}
                    onMouseOver={e => e.currentTarget.style.borderColor = "var(--accent)"}
                    onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                    <div style={{ fontSize: 14, fontWeight: 700, color: "var(--accent)", marginBottom: 4 }}>{g.name}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                      {g.description || "Ransomware group"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Analytics (GLOBAL) ══════════════════════════════ */}
      {tab === "analytics" && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title">Global Attack Timeline (Last 30 Days)</div>
            <Sparkline data={dashboard?.timeline || []} />
            {(dashboard?.timeline || []).length > 0 && (
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                <span>{dashboard.timeline[0]?.date}</span>
                <span>{dashboard.timeline[dashboard.timeline.length - 1]?.date}</span>
              </div>
            )}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div className="card">
              <div className="card-title">Top Targeted Countries (Worldwide)</div>
              <MiniBar data={(dashboard?.all_countries || []).slice(0, 15).map(c => ({
                label: `${countryFlag(c.code)} ${c.name}`,
                count: c.count,
                color: c.code === "US" ? "var(--info)" : c.code === "IN" ? "var(--warning)" : "var(--accent)",
              }))} />
            </div>
            <div className="card">
              <div className="card-title">Top Targeted Sectors</div>
              <MiniBar data={(dashboard?.top_sectors || []).slice(0, 10).map(s => ({
                label: s.sector,
                count: s.count,
                color: "var(--warning)",
              }))} />
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title">Most Active Ransomware Groups (Global)</div>
            <MiniBar data={(dashboard?.top_groups || []).slice(0, 12).map(g => ({
              label: g.name,
              count: g.count,
              color: "var(--high-risk)",
            }))} />
          </div>
        </div>
      )}

      {/* ═══ TAB: Search ══════════════════════════════════════════ */}
      {tab === "search" && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title">Search Global Ransomware Victims</div>
            <div style={{ display: "flex", gap: 8 }}>
              <input type="text" placeholder="Enter company name, domain, or keyword..."
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
            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
              {searchResults.length === 0 ? (
                <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No victims found for "{searchQuery}"
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 500 }}>
                    <thead>
                      <tr style={{ background: "var(--bg-tertiary)" }}>
                        <th style={thStyle}>When</th>
                        <th style={thStyle}>Group</th>
                        <th style={thStyle}>Victim</th>
                        <th style={thStyle}>Country</th>
                      </tr>
                    </thead>
                    <tbody>
                      {searchResults.map((v, i) => (
                        <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                          <td style={tdStyle}><span className="mono" style={{ fontSize: 11 }}>{timeAgo(v.discovered)}</span></td>
                          <td style={tdStyle}><span style={{ color: "var(--accent)", fontWeight: 600, fontSize: 12 }}>{v.group_name}</span></td>
                          <td style={tdStyle}>{v.victim}</td>
                          <td style={tdStyle}>{v.country ? `${countryFlag(v.country)} ${v.country_name || v.country}` : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Footer ── */}
      <div style={{ textAlign: "center", padding: "24px 0", marginTop: 32, borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.8 }}>
        Global data sourced from <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)" }}>ransomware.live</a> API
        {" · "} Refreshed every 15 minutes · Covers all countries worldwide
        <br />
        CyberIntelEngine is not responsible for the accuracy of third-party threat intelligence data
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

/* ─── inject responsive + animation styles ──────────────────────── */
if (typeof document !== "undefined") {
  const id = "ransomware-tracker-styles";
  if (!document.getElementById(id)) {
    const style = document.createElement("style");
    style.id = id;
    style.textContent = `
      @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      @media(max-width:768px) {
        .card { overflow-x: auto; }
      }
    `;
    document.head.appendChild(style);
  }
}
