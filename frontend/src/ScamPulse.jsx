import React, { useState, useEffect } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "https://scamcheck-api-india.onrender.com";

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
          <span className="mono" style={{ fontSize: 11, minWidth: 50, textAlign: "right", color: "var(--text-muted)" }}>{d.suffix || d.count}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── color helpers ─────────────────────────────────────────────── */
function riskColor(level) {
  if (level === "critical") return "#ff3d3d";
  if (level === "high") return "#ff8c00";
  if (level === "medium") return "#eab308";
  return "#51cf66";
}

function trendColor(trend) {
  if (trend === "rising") return "#ff3d3d";
  if (trend === "stable") return "#eab308";
  return "#51cf66";
}

function trendLabel(trend) {
  if (trend === "rising") return "Rising";
  if (trend === "stable") return "Stable";
  return "Declining";
}

/* ─── tweet builders (Krebs/Cluley voice) ──────────────────────── */
function buildScamTweet(cat) {
  const name = cat.name || "";
  const losses = cat.losses_formatted || "";
  const trend = cat.global_trend || "";

  const templates = [
    `${name} accounts for an estimated ${losses} in annual losses globally and the trend is ${trend}. ${cat.common_methods ? cat.common_methods[0] + " remains the most common vector." : ""} A reminder to verify before you trust or pay. https://cyberintelengine.com`,
    `Global ${name.toLowerCase()} activity is currently ${trend}, with estimated annual losses of ${losses}. Know the red flags before you become a statistic. https://cyberintelengine.com`,
    `${losses} lost to ${name.toLowerCase()} globally each year. The trend is ${trend}. CyberIntelEngine tracks the methods, platforms, and red flags so you can recognize these scams before they reach your wallet. https://cyberintelengine.com`,
    `${name} is one of the most damaging categories of cyber fraud worldwide, with losses estimated at ${losses} per year. The activity trend is currently ${trend}. Stay informed. https://cyberintelengine.com`,
  ];

  return templates[Math.floor(Math.random() * templates.length)];
}

function buildStatsTweet(stats) {
  const total = stats.total_annual_losses_formatted || "$0";
  const rising = stats.rising_count || 0;
  const totalCats = stats.total_categories || 0;
  const topScam = stats.top_scams_by_losses?.[0];

  const templates = [
    `CyberIntelEngine tracks ${totalCats} categories of global cyber fraud, with combined estimated annual losses of ${total}. ${rising} of those categories are trending upward.${topScam ? ` ${topScam.name} leads at ${topScam.losses_formatted} per year.` : ""} https://cyberintelengine.com`,
    `${total} in estimated global annual losses to cyber fraud, across ${totalCats} tracked categories. ${rising} categories are currently rising.${topScam ? ` The costliest: ${topScam.name} at ${topScam.losses_formatted}.` : ""} https://cyberintelengine.com`,
    `Global scam intelligence snapshot: ${totalCats} fraud categories tracked, ${rising} trending upward, combined annual losses estimated at ${total}.${topScam ? ` ${topScam.name} accounts for ${topScam.losses_formatted} of that figure.` : ""} https://cyberintelengine.com`,
  ];

  return templates[Math.floor(Math.random() * templates.length)];
}

function buildComparisonTweet(item) {
  const dir = item.change_pct > 0 ? "up" : item.change_pct < 0 ? "down" : "flat";
  const pct = Math.abs(item.change_pct);
  const templates = [
    `${item.name} activity is ${dir} ${pct}% week over week, according to data tracked by CyberIntelEngine. The overall trend for this category remains ${item.trend}. https://cyberintelengine.com`,
    `Week-over-week change in ${item.name.toLowerCase()} reports: ${dir} ${pct}%. This category is currently rated ${item.risk_level} risk with a ${item.trend} long-term trend. https://cyberintelengine.com`,
  ];
  return templates[Math.floor(Math.random() * templates.length)];
}


/* ═══════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════════════════ */
export function ScamPulse() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("overview");
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [expandedCard, setExpandedCard] = useState(null);
  const [categoryDetail, setCategoryDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

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
    fetch(`${API_BASE}/scampulse/stats`)
      .then(r => r.json())
      .then(data => {
        setStats(data);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  /* ── load category detail ── */
  const loadCategoryDetail = (catId) => {
    setDetailLoading(true);
    setCategoryDetail(null);
    setExpandedCard(catId);
    fetch(`${API_BASE}/scampulse/category/${catId}`)
      .then(r => r.json())
      .then(data => {
        if (!data.error) setCategoryDetail(data);
      })
      .catch(() => {})
      .finally(() => setDetailLoading(false));
  };

  if (loading) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div style={{ textAlign: "center", padding: 80 }}>
          <div className="pulse" style={{ fontSize: 48, marginBottom: 16 }}>&#x1F4CA;</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Loading Scam Intelligence...</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Aggregating global fraud trend data</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto", padding: 20 }}>
        <div className="card" style={{ textAlign: "center", padding: 40, borderColor: "var(--accent)" }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>&#x26A0;</div>
          <div style={{ color: "var(--accent)", fontWeight: 600, marginBottom: 8 }}>Unable to load scam trend data</div>
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
          Scam Pulse
        </h2>
        <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Global scam trend intelligence. Categories, methods, red flags, and estimated losses tracked in real time.
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 20, overflowX: "auto", paddingBottom: 4 }}>
        {[
          ["overview", "Overview"],
          ["trends", "Trends"],
          ["intel", "Scam Intel"],
        ].map(([key, label]) => (
          <button key={key} onClick={() => { setTab(key); setExpandedCard(null); setCategoryDetail(null); }}
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
          {/* Stats overview */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10, marginBottom: 20 }}>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--accent)" }}>{stats.total_categories}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Scam Categories</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#ff3d3d" }}>{stats.total_annual_losses_formatted}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Est. Annual Losses</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#ff8c00" }}>{stats.rising_count}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Trends Rising</div>
            </div>
            <div className="card" style={{ textAlign: "center", padding: 16 }}>
              <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "#ff3d3d" }}>{stats.critical_count}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.6 }}>Critical Risk</div>
            </div>
          </div>

          {/* Share Stats Tweet */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <button onClick={() => copyTweet(buildStatsTweet(stats), "stats")}
              style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, border: `1px solid ${copiedIndex === "stats" ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === "stats" ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === "stats" ? "#51cf66" : "var(--text-secondary)", cursor: "pointer" }}>
              {copiedIndex === "stats" ? "Copied!" : "Copy Stats Tweet"}
            </button>
          </div>

          {/* Top scams by losses */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">Scam Categories by Estimated Annual Losses</div>
            <MiniBar data={(stats.top_scams_by_losses || []).map(s => ({
              label: s.name,
              count: s.losses_usd,
              suffix: s.losses_formatted,
              color: riskColor(s.risk_level),
            }))} />
          </div>

          {/* Week-over-week comparison cards */}
          <div className="card-title" style={{ marginBottom: 12 }}>Week-over-Week Activity Change</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 10, marginBottom: 20 }}>
            {(stats.week_comparisons || []).map((item, i) => {
              const isUp = item.change_pct > 0;
              const isDown = item.change_pct < 0;
              const changeColor = isUp ? "#ff3d3d" : isDown ? "#51cf66" : "var(--text-muted)";
              const arrow = isUp ? "↑" : isDown ? "↓" : "→";

              return (
                <div key={i} className="card" style={{ padding: 14 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>{item.name}</div>
                    <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${riskColor(item.risk_level)}20`, color: riskColor(item.risk_level), border: `1px solid ${riskColor(item.risk_level)}40` }}>
                      {item.risk_level}
                    </span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: changeColor }}>
                      {arrow} {Math.abs(item.change_pct)}%
                    </span>
                    <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${trendColor(item.trend)}15`, color: trendColor(item.trend) }}>
                      {trendLabel(item.trend)}
                    </span>
                  </div>
                  <button onClick={() => copyTweet(buildComparisonTweet(item), `comp-${i}`)}
                    style={{ width: "100%", padding: "5px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `comp-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `comp-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `comp-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer" }}>
                    {copiedIndex === `comp-${i}` ? "Copied!" : "Copy Tweet"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══ TAB: Trends ══════════════════════════════════════════════ */}
      {tab === "trends" && stats && (
        <div>
          {/* Filter badges */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: "28px" }}>Filter:</span>
            {["all", "rising", "stable", "declining"].map(f => (
              <button key={f} onClick={() => setExpandedCard(f === expandedCard ? null : f)}
                style={{
                  padding: "5px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600,
                  border: "1px solid var(--border)", cursor: "pointer",
                  background: expandedCard === f ? "var(--accent)" : "var(--bg-secondary)",
                  color: expandedCard === f ? "white" : "var(--text-secondary)",
                }}>
                {f === "all" ? "All" : trendLabel(f)}
              </button>
            ))}
          </div>

          {/* Category trend cards */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {(stats.top_scams_by_losses || [])
              .filter(s => !expandedCard || expandedCard === "all" || s.trend === expandedCard)
              .map((s, i) => (
              <div key={i} className="card" style={{
                padding: 16, transition: "border-color 0.2s", cursor: "pointer",
              }}
                onClick={() => { setTab("intel"); loadCategoryDetail(s.id); }}
                onMouseOver={e => e.currentTarget.style.borderColor = riskColor(s.risk_level)}
                onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 15, fontWeight: 700, color: "var(--text-primary)" }}>{s.name}</span>
                      <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${riskColor(s.risk_level)}15`, color: riskColor(s.risk_level), border: `1px solid ${riskColor(s.risk_level)}30` }}>
                        {s.risk_level}
                      </span>
                      <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${trendColor(s.trend)}15`, color: trendColor(s.trend) }}>
                        {trendLabel(s.trend)}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      Estimated annual losses: <span className="mono" style={{ fontWeight: 700, color: "var(--text-secondary)" }}>{s.losses_formatted}</span>
                      <span style={{ marginLeft: 12, fontSize: 10, color: "var(--text-muted)" }}>Click for full intel</span>
                    </div>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); copyTweet(buildScamTweet(s), `trend-${i}`); }}
                    style={{ padding: "6px 12px", borderRadius: 5, fontSize: 11, fontWeight: 600, border: `1px solid ${copiedIndex === `trend-${i}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`, background: copiedIndex === `trend-${i}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)", color: copiedIndex === `trend-${i}` ? "#51cf66" : "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0 }}>
                    {copiedIndex === `trend-${i}` ? "Copied!" : "Copy Tweet"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══ TAB: Scam Intel ══════════════════════════════════════════ */}
      {tab === "intel" && (
        <div>
          {/* Category list */}
          {!expandedCard && (
            <div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 16, lineHeight: 1.6 }}>
                Select a scam category to view the full intelligence profile: methods, platforms, red flags, and estimated losses.
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 10 }}>
                {(stats?.top_scams_by_losses || []).map((s, i) => (
                  <div key={i} className="card" onClick={() => loadCategoryDetail(s.id)}
                    style={{ cursor: "pointer", padding: 16, transition: "border-color 0.2s" }}
                    onMouseOver={e => e.currentTarget.style.borderColor = riskColor(s.risk_level)}
                    onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <span style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)" }}>{s.name}</span>
                      <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${riskColor(s.risk_level)}15`, color: riskColor(s.risk_level) }}>
                        {s.risk_level}
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span className="mono" style={{ fontSize: 16, fontWeight: 700, color: "var(--accent)" }}>{s.losses_formatted}</span>
                      <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${trendColor(s.trend)}15`, color: trendColor(s.trend) }}>
                        {trendLabel(s.trend)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Category detail view */}
          {expandedCard && (
            <div>
              <button onClick={() => { setExpandedCard(null); setCategoryDetail(null); }}
                style={{ padding: "6px 14px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-secondary)", cursor: "pointer", fontSize: 12, marginBottom: 16 }}>
                Back to All Categories
              </button>

              {detailLoading ? (
                <div style={{ textAlign: "center", padding: 60 }}>
                  <div className="pulse" style={{ fontSize: 36, marginBottom: 12 }}>&#x1F50D;</div>
                  <div style={{ fontSize: 15, fontWeight: 600 }}>Loading scam intelligence...</div>
                </div>
              ) : categoryDetail ? (
                <div>
                  {/* Profile header */}
                  <div className="card" style={{ marginBottom: 16, borderColor: `${riskColor(categoryDetail.risk_level)}40`, background: `linear-gradient(135deg, var(--bg-secondary) 0%, ${riskColor(categoryDetail.risk_level)}08 100%)` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
                      <div style={{ flex: 1, minWidth: 200 }}>
                        <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 1.5, color: "var(--text-muted)", marginBottom: 4 }}>Scam Intelligence Profile</div>
                        <div style={{ fontSize: 22, fontWeight: 800, color: riskColor(categoryDetail.risk_level), marginBottom: 8 }}>{categoryDetail.name}</div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
                          <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: `${riskColor(categoryDetail.risk_level)}15`, color: riskColor(categoryDetail.risk_level), border: `1px solid ${riskColor(categoryDetail.risk_level)}30` }}>
                            {categoryDetail.risk_level} risk
                          </span>
                          <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: `${trendColor(categoryDetail.global_trend)}15`, color: trendColor(categoryDetail.global_trend) }}>
                            Trend: {trendLabel(categoryDetail.global_trend)}
                          </span>
                          <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border)" }}>
                            Est. losses: {categoryDetail.losses_formatted}/year
                          </span>
                        </div>
                        <div style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.8 }}>
                          {categoryDetail.description}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Common methods + platforms */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                    <div className="card">
                      <div className="card-title" style={{ fontSize: 12 }}>Common Methods</div>
                      {(categoryDetail.common_methods || []).map((m, i) => (
                        <div key={i} style={{ padding: "8px 0", borderBottom: i < categoryDetail.common_methods.length - 1 ? "1px solid var(--border)" : "none", fontSize: 13, color: "var(--text-secondary)" }}>
                          {m}
                        </div>
                      ))}
                    </div>
                    <div className="card">
                      <div className="card-title" style={{ fontSize: 12 }}>Common Platforms</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                        {(categoryDetail.common_platforms || []).map((p, i) => (
                          <span key={i} style={{ padding: "5px 12px", borderRadius: 6, fontSize: 12, fontWeight: 500, background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border)" }}>
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Red flags */}
                  <div className="card" style={{ marginBottom: 16, borderColor: "rgba(255,61,61,0.2)" }}>
                    <div className="card-title" style={{ color: "var(--accent)", fontSize: 12 }}>Red Flags to Watch For</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {(categoryDetail.red_flags || []).map((flag, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: 10, background: "rgba(255,61,61,0.04)", borderRadius: 8, border: "1px solid rgba(255,61,61,0.1)" }}>
                          <span style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>&#x26A0;</span>
                          <span style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>{flag}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Tweet button */}
                  <button onClick={() => copyTweet(buildScamTweet(categoryDetail), `detail-${expandedCard}`)}
                    style={{
                      padding: "10px 18px", borderRadius: 6, fontSize: 13, fontWeight: 600,
                      border: `1px solid ${copiedIndex === `detail-${expandedCard}` ? "rgba(81,207,102,0.4)" : "var(--border)"}`,
                      background: copiedIndex === `detail-${expandedCard}` ? "rgba(81,207,102,0.1)" : "var(--bg-secondary)",
                      color: copiedIndex === `detail-${expandedCard}` ? "#51cf66" : "var(--text-secondary)",
                      cursor: "pointer",
                    }}>
                    {copiedIndex === `detail-${expandedCard}` ? "Copied!" : "Copy Tweet"}
                  </button>
                </div>
              ) : (
                <div className="card" style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  Category not found.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "24px 0", marginTop: 32, borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.8 }}>
        Scam intelligence curated from FBI IC3, FTC, Europol, INTERPOL, and Action Fraud public reports
        {" / "}Categories and losses are estimates based on published global data
        <br />
        CyberIntelEngine does not guarantee the accuracy of estimated figures
      </div>
    </div>
  );
}
