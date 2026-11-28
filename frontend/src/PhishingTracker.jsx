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

function countryFlag(code) {
  if (!code || code.length !== 2) return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
}

/* ─── mini bar chart (pure CSS) ─────────────────────────────────── */
function MiniBar({ data }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div>
      {data.map((d, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: 11, minWidth: 100, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.label}</span>
          <div style={{ flex: 1, background: "var(--bg-tertiary)", borderRadius: 3, height: 14, overflow: "hidden" }}>
            <div style={{ width: `${(d.count / max) * 100}%`, height: "100%", background: d.color || "var(--accent)", borderRadius: 3, transition: "width 0.3s" }} />
          </div>
          <span className="mono" style={{ fontSize: 11, minWidth: 30, textAlign: "right", color: "var(--text-muted)" }}>{d.count}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── tweet builder (Krebs/Cluley voice) ───────────────────────── */
function buildPhishingTweet(entry) {
  const brand = entry.target_brand || "Unknown";
  const domain = entry.domain || "";
  const country = entry.hosting_country_name || "";
  const source = entry.source || "";
  const srcName = source === "phishtank" ? "PhishTank" : source === "phishunt" ? "Phishunt" : source === "urlhaus" ? "URLhaus" : "threat intelligence feeds";
  const hasBrand = brand && brand !== "Unknown";
  const hasCountry = !!country;

  const templates = [];

  if (hasBrand && hasCountry) {
    templates.push(
      `Fresh ${brand} phishing page at ${domain}, hosted in ${country}. The domain is flagged by ${srcName} and appears to be harvesting login credentials. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `Someone stood up a fake ${brand} login page at ${domain}. Infrastructure is in ${country}. If this domain showed up in your inbox, it is not what it claims to be. https://cyberintelengine.com #Phishing #InfoSec`,
      `${domain} is impersonating ${brand}. Hosting traced to ${country}. The page is designed to capture credentials and was flagged by ${srcName}. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `A credential harvesting page targeting ${brand} customers went live at ${domain}. The site is running out of ${country} and has been confirmed malicious by ${srcName}. https://cyberintelengine.com #Phishing #InfoSec`,
    );
  } else if (hasBrand) {
    templates.push(
      `${domain} is running a fake ${brand} login page. The site was recently registered and is already flagged as malicious by ${srcName}. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `New credential harvesting page targeting ${brand} users at ${domain}. Confirmed by ${srcName}. If you got a link pointing here, don't use it. https://cyberintelengine.com #Phishing #InfoSec`,
      `A phishing page spoofing ${brand} has appeared at ${domain}. It is designed to steal login credentials. The domain is flagged across multiple threat feeds. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `${brand} users should be aware that ${domain} is serving a fake login page. The site showed up recently and is already on threat intelligence blocklists. https://cyberintelengine.com #Phishing #InfoSec`,
    );
  } else if (hasCountry) {
    templates.push(
      `Malicious domain ${domain} is hosting a phishing page out of ${country}. Currently flagged by ${srcName}. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `${domain}, hosted in ${country}, has been flagged for serving phishing content. The domain appeared recently and is already on blocklists via ${srcName}. https://cyberintelengine.com #Phishing #InfoSec`,
    );
  } else {
    templates.push(
      `${domain} has been flagged as a phishing site by ${srcName}. The domain is serving content designed to steal credentials. https://cyberintelengine.com #Phishing #CyberSecurity`,
      `Phishing infrastructure detected at ${domain}. The site is confirmed malicious across threat intelligence feeds. https://cyberintelengine.com #Phishing #InfoSec`,
    );
  }

  return templates[Math.floor(Math.random() * templates.length)];
}

function buildStatsTweet(stats) {
  const topBrand = stats.top_brands?.[0]?.brand || "Unknown";
  const topBrandCount = stats.top_brands?.[0]?.count || 0;
  const topCountry = stats.top_hosting_countries?.[0]?.country || "Unknown";
  const secondBrand = stats.top_brands?.[1]?.brand || "";

  const templates = [
    `${stats.recent_24h} new phishing sites went live in the past 24 hours. ${topBrand} is the most impersonated brand right now with ${topBrandCount} active fake pages. Most of the infrastructure is hosted in ${topCountry}. Full data at https://cyberintelengine.com #Phishing #CyberSecurity`,
    `We are tracking ${stats.total} active phishing sites right now. ${topBrand} leads the target list${secondBrand ? `, followed by ${secondBrand}` : ""}. ${topCountry} hosts more phishing infrastructure than any other country in the current dataset. https://cyberintelengine.com #Phishing #InfoSec`,
    `${stats.total} phishing sites. ${stats.recent_24h} of them appeared in the last day. ${topBrand} remains the brand attackers impersonate most often, and ${topCountry} remains the top hosting country. The numbers keep climbing. https://cyberintelengine.com #Phishing #CyberSecurity`,
    `Today's phishing numbers: ${stats.total} active sites tracked across multiple threat feeds, ${stats.recent_24h} new in 24 hours. ${topBrand} accounts for ${topBrandCount} of those pages. Most of the hosting runs through ${topCountry}. https://cyberintelengine.com #Phishing #InfoSec`,
  ];

  return templates[Math.floor(Math.random() * templates.length)];
}


/* ═══════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════════════════ */
export function PhishingTracker() {
  const [stats, setStats] = useState(null);
  const [feed, setFeed] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("feed");
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [feedLimit, setFeedLimit] = useState(50);
  const [expandedCard, setExpandedCard] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [brandFilter, setBrandFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");

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
      fetch(`${API_BASE}/phishing/stats`).then(r => r.json()),
      fetch(`${API_BASE}/phishing/feed?limit=500`).then(r => r.json()),
    ])
      .then(([statsData, feedData]) => {
        setStats(statsData);
        setFeed(Array.isArray(feedData) ? feedData : []);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  /* ── search ── */
  const doSearch = () => {
    if (!searchQuery.trim()) return;
    setSearchLoading(true);
    setSearchResults(null);
    fetch(`${API_BASE}/phishing/search/${encodeURIComponent(searchQuery.trim())}`)
      .then(r => r.json())
      .then(data => setSearchResults(Array.isArray(data) ? data : []))
      .catch(() => setSearchResults([]))
      .finally(() => setSearchLoading(false));
  };

  /* ── filtered feed ── */
  const filteredFeed = useMemo(() => {
    let result = feed;
    if (brandFilter) {
      result = result.filter(e => (e.target_brand || "").toLowerCase() === brandFilter.toLowerCase());
    }
    if (categoryFilter) {
      result = result.filter(e => (e.target_category || "") === categoryFilter);
    }
    if (sourceFilter) {
      result = result.filter(e => (e.source || "") === sourceFilter);
    }
    return result;
  }, [feed, brandFilter, categoryFilter, sourceFilter]);

  /* ── verdict color ── */
  const verdictStyle = (verdict) => {
    if (verdict === "critical" || verdict === "verified") return { bg: "rgba(255,61,61,0.12)", color: "#ff3d3d", border: "rgba(255,61,61,0.25)" };
    if (verdict === "high") return { bg: "rgba(255,140,0,0.12)", color: "#ff8c00", border: "rgba(255,140,0,0.25)" };
    if (verdict === "medium") return { bg: "rgba(234,179,8,0.12)", color: "#eab308", border: "rgba(234,179,8,0.25)" };
    return { bg: "var(--bg-tertiary)", color: "var(--text-muted)", border: "var(--border)" };
  };

  /* ── source label ── */
  const sourceLabel = (src) => {
    if (src === "phishunt") return "Phishunt";
    if (src === "phishtank") return "PhishTank";
    if (src === "urlhaus") return "URLhaus";
    return src;
  };

  if (loading) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div style={{ textAlign: "center", padding: 80 }}>
          <div className="pulse" style={{ fontSize: 48, marginBottom: 16 }}>&#x1F3A3;</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Loading Phishing Intelligence...</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Aggregating from multiple threat feeds</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div className="card" style={{ textAlign: "center", padding: 40, borderColor: "var(--accent)" }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>&#x26A0;</div>
          <div style={{ color: "var(--accent)", fontWeight: 600, marginBottom: 8 }}>Unable to load phishing data</div>
          <div style={{ color: "var(--text-muted)", fontSize: 13 }}>{error}</div>
          <button onClick={() => window.location.reload()} className="cta-btn" style={{ marginTop: 16, padding: "8px 24px", fontSize: 13 }}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 24, fontWeight: 800, letterSpacing: -0.5, marginBottom: 4 }}>
          Phishing Intelligence Tracker
        </h2>
        <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Real-time phishing site detection aggregated from PhishTank, Phishunt.io, and URLhaus
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 20, overflowX: "auto", paddingBottom: 4 }}>
        {[
          ["feed", "Live Feed"],
          ["brands", "Targeted Brands"],
          ["analytics", "Analytics"],
          ["search", "Search"],
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

      {/* ═══ TAB: Live Feed ═══════════════════════════════════════════ */}
      {tab === "feed" && (
        <div>
          {/* Stats overview */}
          {stats && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10, marginBottom: 20 }}>
              <div className="card" style={{ textAlign: "center", padding: 16 }}>
                <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--accent)" }}>{stats.total}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Active Phishing Sites</div>
              </div>
              <div className="card" style={{ textAlign: "center", padding: 16 }}>
                <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#ff8c00" }}>{stats.recent_24h}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>New (24h)</div>
              </div>
              <div className="card" style={{ textAlign: "center", padding: 16 }}>
                <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--info)" }}>{stats.top_brands?.length || 0}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Brands Targeted</div>
              </div>
              <div className="card" style={{ textAlign: "center", padding: 16 }}>
                <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#51cf66" }}>{stats.online_count}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Confirmed Online</div>
              </div>
            </div>
          )}

          {/* Share Stats Tweet */}
          {stats && (
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
              <button onClick={() => copyTweet(buildStatsTweet(stats), "stats")}
                style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: `1px solid ${copiedIndex === "stats" ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === "stats" ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === "stats" ? "#51cf66" : "var(--text-secondary)", cursor: "pointer" }}>
                {copiedIndex === "stats" ? "Copied!" : "Copy Stats Tweet"}
              </button>
            </div>
          )}

          {/* Filters */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setFeedLimit(50); setExpandedCard(null); }}
              style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 12 }}>
              <option value="">All Sources</option>
              <option value="phishunt">Phishunt</option>
              <option value="phishtank">PhishTank</option>
              <option value="urlhaus">URLhaus</option>
            </select>
            <select value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value); setFeedLimit(50); setExpandedCard(null); }}
              style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 12 }}>
              <option value="">All Categories</option>
              {(stats?.top_categories || []).map(c => (
                <option key={c.category} value={c.category}>{c.category} ({c.count})</option>
              ))}
            </select>
            {brandFilter && (
              <button onClick={() => { setBrandFilter(""); setFeedLimit(50); }}
                style={{ padding: "6px 12px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: "1px solid var(--accent)", background: "rgba(255,61,61,0.1)", color: "var(--accent)", cursor: "pointer" }}>
                Brand: {brandFilter} &#x2715;
              </button>
            )}
          </div>

          {/* Feed count */}
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, display: "flex", justifyContent: "space-between" }}>
            <span>Showing {Math.min(filteredFeed.length, feedLimit)} of {filteredFeed.length} phishing sites</span>
            <span>Updated: {stats?.last_updated ? new Date(stats.last_updated).toLocaleString("en-IN") : "..."}</span>
          </div>

          {/* Feed cards */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {filteredFeed.slice(0, feedLimit).map((entry, i) => {
              const isExpanded = expandedCard === i;
              const vs = verdictStyle(entry.verdict);

              return (
                <div key={i} className="card" style={{
                  padding: 0, transition: "border-color 0.2s",
                  borderColor: isExpanded ? "#ff8c00" : undefined,
                }}
                  onMouseOver={e => { if (!isExpanded) e.currentTarget.style.borderColor = "rgba(255,140,0,0.4)"; }}
                  onMouseOut={e => { if (!isExpanded) e.currentTarget.style.borderColor = "var(--border)"; }}>

                  {/* Card header */}
                  <div style={{ padding: 14, cursor: "pointer" }} onClick={() => setExpandedCard(isExpanded ? null : i)}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                          <span style={{ padding: "3px 10px", borderRadius: 5, fontSize: 11, fontWeight: 700, background: vs.bg, color: vs.color, border: `1px solid ${vs.border}` }}>
                            {(entry.verdict || "detected").toUpperCase()}
                          </span>
                          {entry.target_brand && entry.target_brand !== "Unknown" && (
                            <span onClick={(e) => { e.stopPropagation(); setBrandFilter(entry.target_brand); setTab("feed"); }}
                              style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "rgba(59,130,246,0.12)", color: "var(--info)", border: "1px solid rgba(59,130,246,0.25)", cursor: "pointer" }}>
                              {entry.target_brand}
                            </span>
                          )}
                          <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 500, background: "var(--bg-tertiary)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
                            {sourceLabel(entry.source)}
                          </span>
                          {entry.hosting_country && (
                            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                              {countryFlag(entry.hosting_country)} {entry.hosting_country_name || entry.hosting_country}
                            </span>
                          )}
                          <span className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>{timeAgo(entry.first_seen)}</span>
                        </div>
                        <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 4, wordBreak: "break-all" }}>
                          {entry.domain}
                        </div>
                        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12, alignItems: "center" }}>
                          {entry.target_category && entry.target_category !== "Other" && (
                            <span style={{ color: "var(--text-secondary)" }}>{entry.target_category}</span>
                          )}
                          {entry.ip_address && (
                            <span className="mono" style={{ color: "var(--text-muted)", fontSize: 11 }}>IP: {entry.ip_address}</span>
                          )}
                          <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>
                            {isExpanded ? "Less" : "Details"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div style={{ borderTop: "1px solid var(--border)", background: "var(--bg-tertiary)", padding: 16 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 14 }}>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Full URL</div>
                          <div className="mono" style={{ fontSize: 11, color: "var(--text-primary)", wordBreak: "break-all" }}>{entry.url}</div>
                        </div>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Target Brand</div>
                          <div style={{ fontSize: 13, color: "var(--text-primary)", fontWeight: 600 }}>{entry.target_brand || "Unknown"}</div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{entry.target_category}</div>
                        </div>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>First Seen</div>
                          <div className="mono" style={{ fontSize: 13, color: "var(--text-primary)" }}>
                            {entry.first_seen ? new Date(entry.first_seen.replace(" ", "T")).toLocaleString("en-IN") : "Unknown"}
                          </div>
                        </div>
                        <div style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 4 }}>Hosting</div>
                          <div style={{ fontSize: 13, color: "var(--text-primary)" }}>
                            {entry.hosting_country ? `${countryFlag(entry.hosting_country)} ${entry.hosting_country_name}` : "Unknown"}
                          </div>
                          {entry.ip_address && <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{entry.ip_address}</div>}
                          {entry.org && <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{entry.org}</div>}
                          {entry.asn && <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>ASN: {entry.asn}</div>}
                        </div>
                      </div>

                      {/* Threat type for URLhaus entries */}
                      {entry.threat_type && (
                        <div style={{ padding: 10, background: "rgba(255,61,61,0.06)", borderRadius: 8, border: "1px solid rgba(255,61,61,0.2)", marginBottom: 12, fontSize: 12 }}>
                          <span style={{ color: "var(--accent)", fontWeight: 600 }}>Threat type:</span>{" "}
                          <span style={{ color: "var(--text-secondary)" }}>{entry.threat_type}</span>
                          {entry.tags && entry.tags.length > 0 && (
                            <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>Tags: {entry.tags.join(", ")}</span>
                          )}
                        </div>
                      )}

                      {/* PhishTank link */}
                      {entry.phishtank_url && (
                        <div style={{ padding: 10, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)", marginBottom: 12, fontSize: 12 }}>
                          <span style={{ color: "var(--text-muted)" }}>PhishTank ID: </span>
                          <span className="mono" style={{ color: "var(--info)" }}>{entry.phishtank_id}</span>
                        </div>
                      )}

                      {/* Score */}
                      {entry.score > 0 && (
                        <div style={{ padding: 10, background: "var(--bg-secondary)", borderRadius: 8, border: "1px solid var(--border)", marginBottom: 12, fontSize: 12 }}>
                          <span style={{ color: "var(--text-muted)" }}>Threat score: </span>
                          <span className="mono" style={{ color: entry.score >= 80 ? "#ff3d3d" : entry.score >= 50 ? "#ff8c00" : "var(--text-secondary)", fontWeight: 700 }}>{entry.score}/100</span>
                        </div>
                      )}

                      {/* Action buttons */}
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <button onClick={(e) => { e.stopPropagation(); copyTweet(buildPhishingTweet(entry), `phish-${i}`); }}
                          style={{
                            padding: "8px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600,
                            border: `1px solid ${copiedIndex === `phish-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`,
                            background: copiedIndex === `phish-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)",
                            color: copiedIndex === `phish-${i}` ? "#51cf66" : "var(--text-secondary)",
                            cursor: "pointer",
                          }}>
                          {copiedIndex === `phish-${i}` ? "Copied!" : "Copy Tweet"}
                        </button>
                        {entry.target_brand && entry.target_brand !== "Unknown" && (
                          <button onClick={(e) => { e.stopPropagation(); setBrandFilter(entry.target_brand); setExpandedCard(null); }}
                            style={{ padding: "8px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--info)", cursor: "pointer" }}>
                            All {entry.target_brand} phishing
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {filteredFeed.length > feedLimit && (
            <div style={{ textAlign: "center", marginTop: 16 }}>
              <button onClick={() => setFeedLimit(prev => prev + 50)} className="cta-btn" style={{ padding: "10px 24px", fontSize: 13 }}>
                Load More ({filteredFeed.length - feedLimit} remaining)
              </button>
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Targeted Brands ════════════════════════════════════ */}
      {tab === "brands" && stats && (
        <div>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">Most Impersonated Brands</div>
            <MiniBar data={(stats.top_brands || []).map(b => ({
              label: b.brand,
              count: b.count,
              color: "#ff8c00",
            }))} />
          </div>

          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">Phishing by Category</div>
            <MiniBar data={(stats.top_categories || []).map(c => ({
              label: c.category,
              count: c.count,
              color: "var(--info)",
            }))} />
          </div>

          {/* Brand cards grid */}
          <div className="card-title" style={{ marginBottom: 12 }}>Browse by Brand</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
            {(stats.top_brands || []).map((b, i) => (
              <div key={i} className="card" onClick={() => { setBrandFilter(b.brand); setTab("feed"); setFeedLimit(50); }}
                style={{ cursor: "pointer", padding: 14, transition: "border-color 0.2s" }}
                onMouseOver={e => e.currentTarget.style.borderColor = "#ff8c00"}
                onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#ff8c00", marginBottom: 4 }}>{b.brand}</div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{_categorize_brand_js(b.brand)}</span>
                  <span className="mono" style={{ fontSize: 18, fontWeight: 700, color: "var(--accent)" }}>{b.count}</span>
                </div>
                <div style={{ marginTop: 8 }}>
                  <button onClick={(e) => {
                    e.stopPropagation();
                    const brandTemplates = [
                      `${b.count} active phishing sites are currently impersonating ${b.brand}, according to data tracked by CyberIntelEngine. That makes ${b.brand} one of the most targeted brands in the current phishing landscape. https://cyberintelengine.com #Phishing #CyberSecurity`,
                      `${b.brand} has ${b.count} active phishing pages targeting its users right now. If you receive a login link claiming to be from ${b.brand}, go directly to the official site instead of clicking through. https://cyberintelengine.com #Phishing #InfoSec`,
                      `Attackers are running ${b.count} fake ${b.brand} pages at the moment. The scale of ${b.brand} impersonation continues to grow. Full phishing intelligence at https://cyberintelengine.com #Phishing #CyberSecurity`,
                      `Right now, there are ${b.count} phishing sites pretending to be ${b.brand}. Each one is designed to steal credentials from people who don't look closely at the URL. https://cyberintelengine.com #Phishing #InfoSec`,
                    ];
                    copyTweet(brandTemplates[Math.floor(Math.random() * brandTemplates.length)], `brand-${i}`);
                  }}
                    style={{ padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `brand-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `brand-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `brand-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer", width: "100%" }}>
                    {copiedIndex === `brand-${i}` ? "Copied!" : "Copy Tweet"}
                  </button>
                </div>
              </div>
            ))}
          </div>
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
              <div className="card-title">Top Phishing Hosting Countries</div>
              <MiniBar data={(stats.top_hosting_countries || []).map(c => ({
                label: c.country,
                count: c.count,
                color: "var(--accent)",
              }))} />
            </div>
            <div className="card">
              <div className="card-title">Data Sources</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {Object.entries(stats.sources || {}).map(([src, count]) => (
                  <div key={src} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", background: "var(--bg-tertiary)", borderRadius: 8 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{sourceLabel(src)}</span>
                    <span className="mono" style={{ fontSize: 16, fontWeight: 700, color: "var(--info)" }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-title">Most Impersonated Brands</div>
            <MiniBar data={(stats.top_brands || []).slice(0, 15).map(b => ({
              label: b.brand,
              count: b.count,
              color: "#ff8c00",
            }))} />
          </div>
        </div>
      )}

      {/* ═══ TAB: Search ══════════════════════════════════════════════ */}
      {tab === "search" && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title">Search Phishing Intelligence</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12 }}>
              Search by domain, brand name, URL, or IP address
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input type="text" placeholder="Enter domain, brand, URL, or IP..."
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
                  No phishing sites found for "{searchQuery}"
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10 }}>
                    Found {searchResults.length} results for "{searchQuery}"
                  </div>
                  <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 600 }}>
                        <thead>
                          <tr style={{ background: "var(--bg-tertiary)" }}>
                            <th style={thStyle}>When</th>
                            <th style={thStyle}>Domain</th>
                            <th style={thStyle}>Target</th>
                            <th style={thStyle}>Hosting</th>
                            <th style={thStyle}>Source</th>
                            <th style={thStyle}></th>
                          </tr>
                        </thead>
                        <tbody>
                          {searchResults.map((entry, i) => (
                            <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                              <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{timeAgo(entry.first_seen)}</span></td>
                              <td style={tdStyle}><span className="mono" style={{ fontSize: 11, color: "var(--text-primary)", wordBreak: "break-all" }}>{entry.domain}</span></td>
                              <td style={tdStyle}><span style={{ fontSize: 12, color: "var(--info)", fontWeight: 600 }}>{entry.target_brand}</span></td>
                              <td style={tdStyle}>{entry.hosting_country ? `${countryFlag(entry.hosting_country)} ${entry.hosting_country_name}` : ""}</td>
                              <td style={tdStyle}><span style={{ fontSize: 11 }}>{sourceLabel(entry.source)}</span></td>
                              <td style={tdStyle}>
                                <button onClick={() => copyTweet(buildPhishingTweet(entry), `search-${i}`)}
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

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "24px 0", marginTop: 32, borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.8 }}>
        Phishing intelligence aggregated from PhishTank, Phishunt.io, and URLhaus
        {" / "}Refreshed every 30 minutes
        <br />
        CyberIntelEngine does not guarantee the accuracy of third-party threat intelligence data
      </div>
    </div>
  );
}

/* ─── brand categorizer (JS side) ──────────────────────────────── */
function _categorize_brand_js(brand) {
  if (!brand) return "Other";
  const lower = brand.toLowerCase();
  const map = {
    "Banking": ["paypal","chase","wells fargo","bank of america","citibank","hsbc","barclays","sbi","hdfc","icici","axis","pnb","kotak","anz","westpac","td bank","rbc","dbs","ocbc","uob","santander","bbva","ing","bnp"],
    "Technology": ["microsoft","apple","google","amazon","meta","facebook","instagram","whatsapp","netflix","linkedin","twitter","dropbox","adobe","zoom","slack","yahoo","outlook","office","icloud"],
    "Payment": ["stripe","venmo","cash app","zelle","wise","revolut","paytm","phonepe","gpay","razorpay","coinbase","binance"],
    "Ecommerce": ["ebay","walmart","target","aliexpress","shopify","etsy","flipkart"],
    "Logistics": ["dhl","fedex","ups","usps","royal mail","australia post","india post","canada post"],
    "Government": ["irs","hmrc","ato","aadhaar","epfo","irctc","gov"],
    "Telecom": ["at&t","verizon","t-mobile","vodafone","airtel","jio"],
    "Social Media": ["tiktok","snapchat","telegram","discord","reddit"],
  };
  for (const [cat, brands] of Object.entries(map)) {
    if (brands.some(b => lower.includes(b))) return cat;
  }
  return "Other";
}

/* ─── table styles ──────────────────────────────────────────────── */
const thStyle = {
  textAlign: "left", padding: "10px 12px", fontSize: 11,
  color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6,
  fontWeight: 600, borderBottom: "1px solid var(--border)", whiteSpace: "nowrap",
};
const tdStyle = { padding: "10px 12px", verticalAlign: "top" };
