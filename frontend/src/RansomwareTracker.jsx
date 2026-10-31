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

/* ─── Threat Pulse Score ────────────────────────────────────────── */
function ThreatPulse({ dashboard }) {
  const score = useMemo(() => {
    if (!dashboard) return { value: 0, label: "UNKNOWN", color: "#666" };
    const s = dashboard.stats || {};
    const timeline = dashboard.timeline || [];

    /* Compute score from multiple factors */
    let pts = 0;

    /* Factor 1: volume — how many victims in the recent window */
    const totalVictims = s.total_recent_victims || 0;
    if (totalVictims > 80) pts += 30;
    else if (totalVictims > 50) pts += 22;
    else if (totalVictims > 30) pts += 15;
    else if (totalVictims > 10) pts += 8;
    else pts += 3;

    /* Factor 2: active groups */
    const groups = s.total_groups || 0;
    if (groups > 300) pts += 20;
    else if (groups > 200) pts += 15;
    else if (groups > 100) pts += 10;
    else pts += 5;

    /* Factor 3: geographic spread */
    const countries = s.total_countries_hit || 0;
    if (countries > 15) pts += 20;
    else if (countries > 10) pts += 14;
    else if (countries > 5) pts += 8;
    else pts += 3;

    /* Factor 4: trend — is activity increasing? */
    if (timeline.length >= 3) {
      const recent = timeline.slice(-2).reduce((a, d) => a + d.count, 0);
      const earlier = timeline.slice(0, 2).reduce((a, d) => a + d.count, 0);
      if (recent > earlier * 1.3) pts += 20;
      else if (recent > earlier) pts += 12;
      else pts += 6;
    } else {
      pts += 8;
    }

    /* Factor 5: concentration — is one group dominating? */
    const topCount = s.top_group_count || 0;
    if (topCount > 15) pts += 10;
    else if (topCount > 8) pts += 7;
    else pts += 4;

    const value = Math.min(Math.max(Math.round(pts), 0), 100);
    let label, color;
    if (value >= 80) { label = "CRITICAL"; color = "#ff3d3d"; }
    else if (value >= 60) { label = "HIGH"; color = "#ff8c00"; }
    else if (value >= 40) { label = "ELEVATED"; color = "#ffc107"; }
    else if (value >= 20) { label = "MODERATE"; color = "#4dabf7"; }
    else { label = "LOW"; color = "#51cf66"; }

    return { value, label, color };
  }, [dashboard]);

  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score.value / 100) * circumference;

  return (
    <div className="card" style={{
      padding: 24, marginBottom: 24, textAlign: "center",
      background: `linear-gradient(135deg, var(--bg-secondary) 0%, rgba(${score.color === "#ff3d3d" ? "255,61,61" : score.color === "#ff8c00" ? "255,140,0" : score.color === "#ffc107" ? "255,193,7" : score.color === "#4dabf7" ? "77,171,247" : "81,207,102"},0.06) 100%)`,
      borderColor: `${score.color}33`,
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 32, flexWrap: "wrap" }}>
        {/* Circular gauge */}
        <div style={{ position: "relative", width: 130, height: 130 }}>
          <svg width="130" height="130" viewBox="0 0 130 130" style={{ transform: "rotate(-90deg)" }}>
            <circle cx="65" cy="65" r="54" fill="none" stroke="var(--bg-tertiary)" strokeWidth="10" />
            <circle cx="65" cy="65" r="54" fill="none" stroke={score.color} strokeWidth="10"
              strokeDasharray={circumference} strokeDashoffset={offset}
              strokeLinecap="round" style={{ transition: "stroke-dashoffset 1.5s ease" }} />
          </svg>
          <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", textAlign: "center" }}>
            <div className="mono" style={{ fontSize: 32, fontWeight: 800, color: score.color, lineHeight: 1 }}>{score.value}</div>
            <div style={{ fontSize: 8, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1, marginTop: 2 }}>/ 100</div>
          </div>
        </div>

        {/* Info panel */}
        <div style={{ textAlign: "left" }}>
          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 4 }}>
            Threat Pulse Score
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: score.color, letterSpacing: 2, marginBottom: 8 }}>
            {score.label}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7, maxWidth: 280 }}>
            Based on {dashboard?.stats?.total_recent_victims || 0} recent victims across {dashboard?.stats?.total_countries_hit || 0} countries,
            with {dashboard?.stats?.total_groups || 0} active groups tracked.
            {score.value >= 70 ? " Ransomware activity is significantly above average." :
             score.value >= 45 ? " Ransomware activity is above baseline levels." :
             " Ransomware activity is within normal range."}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 8 }}>
            Updated: {dashboard?.last_updated ? new Date(dashboard.last_updated).toLocaleString("en-IN") : "—"}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Live Attack Map (SVG World Map) ──────────────────────────── */
function AttackMap({ countries }) {
  if (!countries || countries.length === 0) return null;

  /* Simplified world map coordinates — major countries with approximate center lat/lng */
  const countryCoords = {
    US: [-98, 38], CA: [-106, 56], MX: [-102, 23], BR: [-51, -10], AR: [-64, -34],
    CL: [-71, -35], CO: [-74, 4], PE: [-76, -10], VE: [-66, 7],
    GB: [-2, 54], FR: [2, 47], DE: [10, 51], IT: [12, 42], ES: [-4, 40],
    PT: [-8, 39], NL: [5, 52], BE: [4, 50], CH: [8, 47], AT: [14, 47],
    PL: [20, 52], CZ: [15, 50], SE: [15, 62], NO: [10, 62], FI: [26, 64],
    DK: [10, 56], IE: [-8, 53], RO: [25, 46], HU: [19, 47], GR: [22, 39],
    BG: [25, 43], HR: [16, 45], SK: [20, 49], RS: [21, 44], UA: [32, 49],
    RU: [90, 60], TR: [35, 39], IL: [35, 31], SA: [45, 24], AE: [54, 24],
    QA: [51, 25], KW: [48, 29], OM: [57, 21], BH: [50, 26], JO: [36, 31],
    LB: [36, 34], IQ: [44, 33], IR: [53, 32], PK: [69, 30], IN: [79, 22],
    BD: [90, 24], LK: [81, 8], NP: [84, 28], MM: [96, 22], TH: [100, 15],
    VN: [106, 16], MY: [102, 4], SG: [104, 1], ID: [120, -5], PH: [122, 12],
    CN: [105, 35], JP: [138, 36], KR: [128, 36], TW: [121, 24],
    AU: [134, -25], NZ: [174, -41], ZA: [25, -29], NG: [8, 10], KE: [38, 0],
    EG: [30, 27], MA: [-6, 32], TN: [9, 34], GH: [0, 8], ET: [40, 9],
    DZ: [3, 28], LY: [17, 27], SD: [30, 15], TZ: [35, -6], UG: [32, 1],
  };

  /* Map longitude/latitude to SVG x/y (simple equirectangular) */
  const mapW = 800, mapH = 400;
  const toX = lng => ((lng + 180) / 360) * mapW;
  const toY = lat => ((90 - lat) / 180) * mapH;

  const maxCount = Math.max(...countries.map(c => c.count), 1);

  return (
    <div className="card" style={{ padding: 20, marginBottom: 24, overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div className="card-title" style={{ marginBottom: 0 }}>Live Global Attack Map</div>
        <div style={{ display: "flex", gap: 12, fontSize: 10, color: "var(--text-muted)" }}>
          <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: "#ffc107", marginRight: 4 }}/>1-3</span>
          <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: "#ff8c00", marginRight: 4 }}/>4-10</span>
          <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: "#ff3d3d", marginRight: 4 }}/>10+</span>
        </div>
      </div>
      <div style={{ overflowX: "auto" }}>
        <svg viewBox={`0 0 ${mapW} ${mapH}`} style={{ width: "100%", minWidth: 500, height: "auto", background: "rgba(0,0,0,0.2)", borderRadius: 8 }}>
          {/* Grid lines for visual reference */}
          {[0, 1, 2, 3, 4].map(i => (
            <line key={`h${i}`} x1="0" y1={i * 100} x2={mapW} y2={i * 100} stroke="rgba(255,255,255,0.04)" strokeWidth="0.5" />
          ))}
          {[0, 1, 2, 3, 4, 5, 6, 7].map(i => (
            <line key={`v${i}`} x1={i * 100} y1="0" x2={i * 100} y2={mapH} stroke="rgba(255,255,255,0.04)" strokeWidth="0.5" />
          ))}
          {/* Equator */}
          <line x1="0" y1={mapH / 2} x2={mapW} y2={mapH / 2} stroke="rgba(255,255,255,0.08)" strokeWidth="0.5" strokeDasharray="4 4" />

          {/* Country attack dots */}
          {countries.map((c, i) => {
            const coords = countryCoords[c.code];
            if (!coords) return null;
            const x = toX(coords[0]);
            const y = toY(coords[1]);
            const size = Math.max(4, Math.min(18, (c.count / maxCount) * 18));
            const color = c.count > 10 ? "#ff3d3d" : c.count > 3 ? "#ff8c00" : "#ffc107";
            const pulseSize = size + 8;
            return (
              <g key={c.code}>
                {/* Pulse ring animation */}
                <circle cx={x} cy={y} r={pulseSize} fill="none" stroke={color} strokeWidth="1" opacity="0.3">
                  <animate attributeName="r" values={`${size};${pulseSize + 6};${size}`} dur="3s" repeatCount="indefinite" begin={`${i * 0.2}s`} />
                  <animate attributeName="opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite" begin={`${i * 0.2}s`} />
                </circle>
                {/* Glow */}
                <circle cx={x} cy={y} r={size + 3} fill={color} opacity="0.15" />
                {/* Main dot */}
                <circle cx={x} cy={y} r={size} fill={color} opacity="0.85" />
                {/* Center highlight */}
                <circle cx={x} cy={y} r={Math.max(2, size * 0.35)} fill="white" opacity="0.6" />
                {/* Label */}
                <text x={x} y={y - size - 5} textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontFamily="monospace">
                  {c.code} ({c.count})
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 8, textAlign: "center" }}>
        Showing attacks across {countries.length} countries · Dot size indicates attack volume
      </div>
    </div>
  );
}

/* ─── Group Kill Chain Knowledge Base ──────────────────────────── */
const GROUP_INTEL = {
  lockbit: {
    aka: ["LockBit 3.0", "LockBit Black"],
    firstSeen: "2019",
    type: "Ransomware-as-a-Service (RaaS)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Phishing emails, exploiting RDP, VPN vulnerabilities (Citrix, Fortinet)", mitre: "T1566, T1133" },
      { stage: "Execution", icon: "⚡", technique: "PowerShell scripts, cobalt strike beacons, custom loaders", mitre: "T1059.001" },
      { stage: "Persistence", icon: "🔗", technique: "Registry run keys, scheduled tasks, DLL hijacking", mitre: "T1547, T1053" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "PsExec, RDP pivoting, SMB exploitation, WMI", mitre: "T1021, T1047" },
      { stage: "Exfiltration", icon: "📤", technique: "StealBit tool, Mega.nz uploads, cloud storage exfil", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "AES-256 + RSA-2048 encryption, shadow copy deletion, wallpaper change", mitre: "T1486, T1490" },
    ],
    summary: "One of the most prolific RaaS operations. Known for fast encryption speed, affiliate program, and bug bounty program for their malware. Triple extortion: encryption + data leak + DDoS.",
  },
  alphv: {
    aka: ["BlackCat", "ALPHV", "Noberus"],
    firstSeen: "2021",
    type: "Ransomware-as-a-Service (RaaS)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Compromised credentials, Exchange vulnerabilities, social engineering", mitre: "T1078, T1190" },
      { stage: "Execution", icon: "⚡", technique: "Rust-based payload, cross-platform (Windows/Linux/ESXi)", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Backdoor accounts, SSH keys, scheduled tasks", mitre: "T1136, T1053" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "Mimikatz, PsExec, RDP, credential dumping", mitre: "T1003, T1021" },
      { stage: "Exfiltration", icon: "📤", technique: "ExMatter tool, custom exfil utilities", mitre: "T1041" },
      { stage: "Impact", icon: "💀", technique: "ChaCha20/AES encryption, ESXi VM targeting, searchable leak site", mitre: "T1486" },
    ],
    summary: "Written in Rust for cross-platform capability. First ransomware with searchable leak site. Known for targeting VMware ESXi environments and large enterprises.",
  },
  clop: {
    aka: ["Cl0p", "TA505", "FIN11"],
    firstSeen: "2019",
    type: "Ransomware / Data Extortion",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Zero-day exploits (MOVEit, GoAnywhere, Accellion), supply chain attacks", mitre: "T1190, T1195" },
      { stage: "Execution", icon: "⚡", technique: "Web shells, SQL injection payloads, file transfer exploitation", mitre: "T1505.003" },
      { stage: "Persistence", icon: "🔗", technique: "Web shells, backdoor implants on file transfer servers", mitre: "T1505" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "Often unnecessary — mass exploitation of internet-facing apps", mitre: "T1210" },
      { stage: "Exfiltration", icon: "📤", technique: "Direct download from compromised file transfer platforms", mitre: "T1530" },
      { stage: "Impact", icon: "💀", technique: "Data theft + extortion (often no encryption), mass victim campaigns", mitre: "T1657" },
    ],
    summary: "Pioneers of mass zero-day exploitation campaigns. MOVEit Transfer exploit affected 2,500+ organizations. Shifted from encryption to pure data extortion model.",
  },
  play: {
    aka: ["PlayCrypt", "Play Ransomware"],
    firstSeen: "2022",
    type: "Ransomware Group",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Exposed RDP, FortiOS vulnerabilities, valid accounts", mitre: "T1133, T1190" },
      { stage: "Execution", icon: "⚡", technique: "Custom tools, AdFind for AD enumeration, GMER for AV disabling", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Scheduled tasks, service creation, Group Policy modification", mitre: "T1053, T1543" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "Cobalt Strike, SystemBC, WinSCP, PsExec", mitre: "T1021" },
      { stage: "Exfiltration", icon: "📤", technique: "WinSCP, WinRAR for staging, split archive uploads", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "Intermittent encryption (faster), .play extension, ransom note in each directory", mitre: "T1486" },
    ],
    summary: "Known for intermittent encryption technique for speed. Targets Latin American organizations heavily. Uses LOLBins extensively to evade detection.",
  },
  royal: {
    aka: ["Royal Ransomware", "Blacksuit"],
    firstSeen: "2022",
    type: "Ransomware Group (ex-Conti members)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Callback phishing, SEO poisoning, malvertising, exposed RDP", mitre: "T1566, T1189" },
      { stage: "Execution", icon: "⚡", technique: "BatLoader, QakBot, Cobalt Strike, custom C2", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Registry modifications, startup scripts", mitre: "T1547" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "PsExec, RDP, Cobalt Strike lateral movement, Mimikatz", mitre: "T1021, T1003" },
      { stage: "Exfiltration", icon: "📤", technique: "Custom exfiltration tools, cloud upload", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "AES + RSA encryption, partial encryption for speed, .royal extension", mitre: "T1486" },
    ],
    summary: "Comprised of former Conti members. Known for callback phishing and targeting healthcare and education sectors. Rebranded as Blacksuit in 2023.",
  },
  "8base": {
    aka: ["8Base"],
    firstSeen: "2022",
    type: "Ransomware / Data Extortion",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Phishing, SmokeLoader delivery, compromised credentials", mitre: "T1566, T1078" },
      { stage: "Execution", icon: "⚡", technique: "SmokeLoader, SystemBC proxy, custom loaders", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Scheduled tasks, registry modifications", mitre: "T1053, T1547" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "Network scanning, credential harvesting, RDP", mitre: "T1021" },
      { stage: "Exfiltration", icon: "📤", technique: "Data staging and upload prior to encryption", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "Phobos-variant encryption, double extortion via leak site", mitre: "T1486" },
    ],
    summary: "Aggressive double-extortion group targeting SMBs worldwide. Uses Phobos ransomware variant. Known for targeting companies across multiple sectors.",
  },
  medusa: {
    aka: ["Medusa Ransomware", "MedusaLocker"],
    firstSeen: "2023",
    type: "Ransomware-as-a-Service (RaaS)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Exploiting public-facing apps, phishing, initial access brokers", mitre: "T1190, T1566" },
      { stage: "Execution", icon: "⚡", technique: "PowerShell, batch scripts, custom tooling", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Web shells, registry run keys, service installation", mitre: "T1505, T1547" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "RDP, PsExec, credential harvesting tools", mitre: "T1021, T1003" },
      { stage: "Exfiltration", icon: "📤", technique: "Rclone, cloud storage upload, custom tools", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "AES-256 encryption, .medusa extension, Tor-based negotiation", mitre: "T1486" },
    ],
    summary: "Rising RaaS group known for targeting education and healthcare. Operates Tor-based leak site with countdown timers. Growing affiliate network.",
  },
  bianlian: {
    aka: ["BianLian"],
    firstSeen: "2022",
    type: "Data Extortion (formerly Ransomware)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Compromised RDP credentials, ProxyShell exploits", mitre: "T1133, T1190" },
      { stage: "Execution", icon: "⚡", technique: "Go-based backdoor, custom tooling written in Go", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "SSH tunneling, reverse proxy (Ngrok), backdoor services", mitre: "T1572, T1090" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "RDP, SMB, network scanning, credential access", mitre: "T1021" },
      { stage: "Exfiltration", icon: "📤", technique: "Rclone to cloud storage, FTP, custom scripts", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "Shifted to pure data extortion (no encryption) in 2023", mitre: "T1657" },
    ],
    summary: "Shifted from encryption to pure data extortion in 2023. Written in Go for cross-platform capability. Known for using Ngrok tunnels for persistence.",
  },
  akira: {
    aka: ["Akira Ransomware"],
    firstSeen: "2023",
    type: "Ransomware-as-a-Service (RaaS)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "VPN vulnerabilities (Cisco ASA/AnyConnect), compromised credentials", mitre: "T1133, T1078" },
      { stage: "Execution", icon: "⚡", technique: "PowerShell, Cobalt Strike, PCHunter for AV evasion", mitre: "T1059, T1562" },
      { stage: "Persistence", icon: "🔗", technique: "New local accounts, scheduled tasks", mitre: "T1136, T1053" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "RDP, RustDesk, AnyDesk, credential dumping", mitre: "T1021, T1003" },
      { stage: "Exfiltration", icon: "📤", technique: "WinSCP, Rclone, FileZilla to cloud storage", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "ChaCha20/RSA encryption, Linux ESXi variant, .akira extension", mitre: "T1486" },
    ],
    summary: "Rapidly growing group with retro-themed leak site. Focuses on exploiting Cisco VPN appliances. Has both Windows and Linux/ESXi variants.",
  },
  rhysida: {
    aka: ["Rhysida Ransomware"],
    firstSeen: "2023",
    type: "Ransomware-as-a-Service (RaaS)",
    killChain: [
      { stage: "Initial Access", icon: "🎯", technique: "Phishing, VPN/RDP exploitation, initial access brokers", mitre: "T1566, T1133" },
      { stage: "Execution", icon: "⚡", technique: "PowerShell, Cobalt Strike, PsExec deployment", mitre: "T1059" },
      { stage: "Persistence", icon: "🔗", technique: "Web shells, scheduled tasks, new user accounts", mitre: "T1505, T1136" },
      { stage: "Lateral Movement", icon: "🕸️", technique: "RDP, PsExec, Mimikatz, ntdsutil for AD dump", mitre: "T1021, T1003" },
      { stage: "Exfiltration", icon: "📤", technique: "Custom tools, cloud uploads, MegaSync", mitre: "T1567" },
      { stage: "Impact", icon: "💀", technique: "ChaCha20 + RSA-4096 encryption, .rhysida extension, PDF ransom note", mitre: "T1486" },
    ],
    summary: "Targets healthcare, education, and government. Positions themselves as a 'cybersecurity team' finding vulnerabilities. Offers stolen data via auction.",
  },
};

/* Map group names to their intel profile keys */
function getGroupIntel(groupName) {
  if (!groupName) return null;
  const lower = groupName.toLowerCase().replace(/[^a-z0-9]/g, "");
  for (const [key, data] of Object.entries(GROUP_INTEL)) {
    if (lower.includes(key) || key.includes(lower)) return data;
    if (data.aka?.some(a => lower.includes(a.toLowerCase().replace(/[^a-z0-9]/g, "")))) return data;
  }
  return null;
}

/* Default kill chain for unknown groups */
const DEFAULT_KILL_CHAIN = [
  { stage: "Initial Access", icon: "🎯", technique: "Phishing, credential compromise, vulnerability exploitation", mitre: "T1566, T1190" },
  { stage: "Execution", icon: "⚡", technique: "Malicious scripts, custom loaders, living-off-the-land binaries", mitre: "T1059" },
  { stage: "Persistence", icon: "🔗", technique: "Registry modifications, scheduled tasks, backdoor services", mitre: "T1547, T1053" },
  { stage: "Lateral Movement", icon: "🕸️", technique: "RDP, PsExec, credential harvesting, network scanning", mitre: "T1021, T1003" },
  { stage: "Exfiltration", icon: "📤", technique: "Data staging and upload to attacker infrastructure", mitre: "T1567" },
  { stage: "Impact", icon: "💀", technique: "File encryption, shadow copy deletion, ransom note deployment", mitre: "T1486, T1490" },
];

/* ─── Kill Chain Visual Component ─────────────────────────────── */
function KillChainDiagram({ chain }) {
  const stageColors = ["#4dabf7", "#748ffc", "#da77f2", "#ff8c00", "#ffc107", "#ff3d3d"];
  return (
    <div style={{ overflowX: "auto" }}>
      <div style={{ display: "flex", gap: 0, minWidth: 700, padding: "8px 0" }}>
        {chain.map((step, i) => (
          <div key={i} style={{ flex: 1, position: "relative" }}>
            {/* Connector arrow */}
            {i < chain.length - 1 && (
              <div style={{
                position: "absolute", right: -8, top: 22, width: 16, height: 2,
                background: `linear-gradient(90deg, ${stageColors[i]}, ${stageColors[i + 1]})`,
                zIndex: 1,
              }}>
                <div style={{
                  position: "absolute", right: -3, top: -3, width: 0, height: 0,
                  borderLeft: `6px solid ${stageColors[i + 1]}`,
                  borderTop: "4px solid transparent",
                  borderBottom: "4px solid transparent",
                }} />
              </div>
            )}
            <div style={{
              background: `${stageColors[i]}11`, border: `1px solid ${stageColors[i]}33`,
              borderRadius: 10, padding: "12px 10px", margin: "0 4px",
              transition: "border-color 0.2s, background 0.2s",
            }}
              onMouseOver={e => { e.currentTarget.style.borderColor = stageColors[i]; e.currentTarget.style.background = `${stageColors[i]}22`; }}
              onMouseOut={e => { e.currentTarget.style.borderColor = `${stageColors[i]}33`; e.currentTarget.style.background = `${stageColors[i]}11`; }}
            >
              {/* Stage header */}
              <div style={{ textAlign: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 20 }}>{step.icon}</span>
                <div style={{ fontSize: 10, fontWeight: 700, color: stageColors[i], textTransform: "uppercase", letterSpacing: 0.5, marginTop: 4 }}>
                  {step.stage}
                </div>
              </div>
              {/* Technique */}
              <div style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.5, textAlign: "center" }}>
                {step.technique}
              </div>
              {/* MITRE ATT&CK */}
              <div style={{ textAlign: "center", marginTop: 8 }}>
                <span className="mono" style={{ fontSize: 9, color: "var(--text-muted)", background: "var(--bg-tertiary)", padding: "2px 6px", borderRadius: 4 }}>
                  {step.mitre}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Group Profile Component ─────────────────────────────────── */
function GroupProfile({ groupName, groupVictims, groupLoading, dashboard, onCountryClick }) {
  const intel = getGroupIntel(groupName);
  const chain = intel?.killChain || DEFAULT_KILL_CHAIN;

  /* Compute stats from victim data */
  const stats = useMemo(() => {
    if (!groupVictims || groupVictims.length === 0) return null;
    const countries = {}, sectors = {};
    let earliest = null, latest = null;
    groupVictims.forEach(v => {
      if (v.country_name) countries[v.country_name] = (countries[v.country_name] || 0) + 1;
      if (v.activity && v.activity !== "Not Found") sectors[v.activity] = (sectors[v.activity] || 0) + 1;
      if (v.discovered) {
        if (!earliest || v.discovered < earliest) earliest = v.discovered;
        if (!latest || v.discovered > latest) latest = v.discovered;
      }
    });
    return {
      topCountries: Object.entries(countries).sort((a, b) => b[1] - a[1]).slice(0, 5),
      topSectors: Object.entries(sectors).sort((a, b) => b[1] - a[1]).slice(0, 5),
      earliest, latest,
    };
  }, [groupVictims]);

  return (
    <div>
      {/* Profile header card */}
      <div className="card" style={{ marginBottom: 16, borderColor: "rgba(255,61,61,0.3)", background: "linear-gradient(135deg, var(--bg-secondary) 0%, rgba(255,61,61,0.04) 100%)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 1.5, color: "var(--text-muted)", marginBottom: 4 }}>Ransomware Group Profile</div>
            <div style={{ fontSize: 24, fontWeight: 800, color: "var(--accent)", marginBottom: 4 }}>{groupName}</div>
            {intel?.aka && (
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
                Also known as: {intel.aka.join(", ")}
              </div>
            )}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              {intel?.type && (
                <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: "rgba(255,140,0,0.15)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.3)" }}>
                  {intel.type}
                </span>
              )}
              {intel?.firstSeen && (
                <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border)" }}>
                  Active since {intel.firstSeen}
                </span>
              )}
              <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: "rgba(255,61,61,0.15)", color: "#ff3d3d", border: "1px solid rgba(255,61,61,0.3)" }}>
                {groupLoading ? "..." : `${groupVictims?.length || 0} victims`}
              </span>
            </div>
            {intel?.summary && (
              <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
                {intel.summary}
              </div>
            )}
            {!intel && (
              <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
                Ransomware group tracked in the wild. The kill chain below shows a typical ransomware attack pattern.
                Specific TTPs may vary. {groupLoading ? "" : `${groupVictims?.length || 0} total victims recorded.`}
              </div>
            )}
          </div>

          {/* Quick stats */}
          {stats && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, minWidth: 180 }}>
              <div style={{ padding: 10, background: "var(--bg-tertiary)", borderRadius: 8, textAlign: "center" }}>
                <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: "var(--info)" }}>{stats.topCountries.length}</div>
                <div style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase" }}>Countries</div>
              </div>
              <div style={{ padding: 10, background: "var(--bg-tertiary)", borderRadius: 8, textAlign: "center" }}>
                <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: "var(--warning)" }}>{stats.topSectors.length}</div>
                <div style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase" }}>Sectors</div>
              </div>
              <div style={{ padding: 10, background: "var(--bg-tertiary)", borderRadius: 8, textAlign: "center", gridColumn: "span 2" }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                  Latest: <span className="mono" style={{ color: "var(--accent)" }}>{timeAgo(stats.latest)}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Kill Chain */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div className="card-title" style={{ marginBottom: 0 }}>
            {intel ? "Known Attack Kill Chain" : "Typical Ransomware Kill Chain"}
          </div>
          <span className="mono" style={{ fontSize: 10, color: "var(--text-muted)", background: "var(--bg-tertiary)", padding: "3px 8px", borderRadius: 4 }}>
            MITRE ATT&CK
          </span>
        </div>
        <KillChainDiagram chain={chain} />
      </div>

      {/* Victim Analysis */}
      {stats && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
          <div className="card">
            <div className="card-title" style={{ fontSize: 12 }}>Top Targeted Countries</div>
            {stats.topCountries.map(([name, count], i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: i < stats.topCountries.length - 1 ? "1px solid var(--border)" : "none" }}>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{name}</span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: i === 0 ? "var(--accent)" : "var(--text-muted)" }}>{count}</span>
              </div>
            ))}
            {stats.topCountries.length === 0 && <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No country data available</div>}
          </div>
          <div className="card">
            <div className="card-title" style={{ fontSize: 12 }}>Top Targeted Sectors</div>
            {stats.topSectors.map(([name, count], i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: i < stats.topSectors.length - 1 ? "1px solid var(--border)" : "none" }}>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{name}</span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: i === 0 ? "var(--warning)" : "var(--text-muted)" }}>{count}</span>
              </div>
            ))}
            {stats.topSectors.length === 0 && <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No sector data available</div>}
          </div>
        </div>
      )}

      {/* Victims table */}
      <div className="card" style={{ marginBottom: 0 }}>
        <div className="card-title" style={{ fontSize: 12 }}>All Claimed Victims ({groupVictims?.length || 0})</div>
      </div>
    </div>
  );
}

/* ─── Risk Assessment Tool ─────────────────────────────────────── */
function RiskAssessment({ dashboard }) {
  const [sector, setSector] = useState("");
  const [country, setCountry] = useState("");
  const [result, setResult] = useState(null);

  const sectors = useMemo(() => {
    if (!dashboard?.top_sectors) return [];
    return dashboard.top_sectors.map(s => s.sector).filter(s => s !== "Not Found");
  }, [dashboard]);

  const allCountries = useMemo(() => {
    if (!dashboard?.all_countries) return [];
    return dashboard.all_countries;
  }, [dashboard]);

  const assess = () => {
    if (!sector && !country) return;
    const victims = dashboard?.recent_victims || [];
    const totalVictims = victims.length || 1;

    /* Sector analysis */
    let sectorCount = 0, sectorGroups = {}, sectorCountries = {};
    if (sector) {
      victims.forEach(v => {
        if ((v.activity || "").toLowerCase() === sector.toLowerCase()) {
          sectorCount++;
          sectorGroups[v.group_name] = (sectorGroups[v.group_name] || 0) + 1;
          if (v.country_name) sectorCountries[v.country_name] = (sectorCountries[v.country_name] || 0) + 1;
        }
      });
    }

    /* Country analysis */
    let countryCount = 0, countryGroups = {}, countrySectors = {};
    if (country) {
      victims.forEach(v => {
        if ((v.country || "").toUpperCase() === country.toUpperCase()) {
          countryCount++;
          countryGroups[v.group_name] = (countryGroups[v.group_name] || 0) + 1;
          if (v.activity) countrySectors[v.activity] = (countrySectors[v.activity] || 0) + 1;
        }
      });
    }

    /* Combined risk calculation */
    let riskScore = 0;
    const sectorPercent = (sectorCount / totalVictims) * 100;
    const countryPercent = (countryCount / totalVictims) * 100;

    if (sector) {
      if (sectorPercent > 12) riskScore += 35;
      else if (sectorPercent > 7) riskScore += 25;
      else if (sectorPercent > 3) riskScore += 15;
      else riskScore += 5;
    }

    if (country) {
      if (countryPercent > 20) riskScore += 40;
      else if (countryPercent > 10) riskScore += 28;
      else if (countryPercent > 5) riskScore += 18;
      else if (countryPercent > 0) riskScore += 10;
      else riskScore += 3;
    }

    /* If both are selected, check overlap */
    if (sector && country) {
      const overlapCount = victims.filter(v =>
        (v.activity || "").toLowerCase() === sector.toLowerCase() &&
        (v.country || "").toUpperCase() === country.toUpperCase()
      ).length;
      if (overlapCount > 0) riskScore += 20;
      else riskScore += 5;
    }

    /* Normalize */
    const maxPossible = sector && country ? 95 : 50;
    riskScore = Math.min(Math.round((riskScore / maxPossible) * 100), 100);

    let riskLevel, riskColor;
    if (riskScore >= 75) { riskLevel = "CRITICAL"; riskColor = "#ff3d3d"; }
    else if (riskScore >= 55) { riskLevel = "HIGH"; riskColor = "#ff8c00"; }
    else if (riskScore >= 35) { riskLevel = "MODERATE"; riskColor = "#ffc107"; }
    else if (riskScore >= 15) { riskLevel = "LOW"; riskColor = "#4dabf7"; }
    else { riskLevel = "MINIMAL"; riskColor = "#51cf66"; }

    const topThreats = Object.entries({ ...sectorGroups, ...countryGroups })
      .sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }));

    setResult({
      riskScore, riskLevel, riskColor,
      sectorCount, countryCount,
      sectorPercent: sectorPercent.toFixed(1),
      countryPercent: countryPercent.toFixed(1),
      topThreats,
      sectorGroups: Object.entries(sectorGroups).sort((a, b) => b[1] - a[1]).slice(0, 3),
      countryGroups: Object.entries(countryGroups).sort((a, b) => b[1] - a[1]).slice(0, 3),
    });
  };

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 4 }}>Is My Company At Risk?</div>
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
          Select your industry and/or country to get a personalized ransomware risk assessment
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 10, alignItems: "end" }}>
          <div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Industry / Sector</div>
            <select value={sector} onChange={e => { setSector(e.target.value); setResult(null); }}
              style={{ width: "100%", padding: "10px 12px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 13 }}>
              <option value="">— Select sector —</option>
              {sectors.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Country</div>
            <select value={country} onChange={e => { setCountry(e.target.value); setResult(null); }}
              style={{ width: "100%", padding: "10px 12px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 13 }}>
              <option value="">— Select country —</option>
              {allCountries.map(c => <option key={c.code} value={c.code}>{countryFlag(c.code)} {c.name}</option>)}
            </select>
          </div>
          <button onClick={assess} className="cta-btn" style={{ padding: "10px 20px", fontSize: 13, whiteSpace: "nowrap" }}
            disabled={!sector && !country}>
            Assess Risk
          </button>
        </div>
      </div>

      {result && (
        <div className="card" style={{
          borderColor: `${result.riskColor}44`,
          background: `linear-gradient(135deg, var(--bg-secondary) 0%, rgba(${result.riskColor === "#ff3d3d" ? "255,61,61" : result.riskColor === "#ff8c00" ? "255,140,0" : result.riskColor === "#ffc107" ? "255,193,7" : result.riskColor === "#4dabf7" ? "77,171,247" : "81,207,102"},0.04) 100%)`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 24, marginBottom: 20, flexWrap: "wrap" }}>
            {/* Risk score circle */}
            <div style={{ position: "relative", width: 90, height: 90, flexShrink: 0 }}>
              <svg width="90" height="90" viewBox="0 0 90 90" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="45" cy="45" r="38" fill="none" stroke="var(--bg-tertiary)" strokeWidth="7" />
                <circle cx="45" cy="45" r="38" fill="none" stroke={result.riskColor} strokeWidth="7"
                  strokeDasharray={2 * Math.PI * 38} strokeDashoffset={2 * Math.PI * 38 - (result.riskScore / 100) * 2 * Math.PI * 38}
                  strokeLinecap="round" style={{ transition: "stroke-dashoffset 1s ease" }} />
              </svg>
              <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", textAlign: "center" }}>
                <div className="mono" style={{ fontSize: 22, fontWeight: 800, color: result.riskColor }}>{result.riskScore}</div>
              </div>
            </div>

            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 20, fontWeight: 800, color: result.riskColor, letterSpacing: 1, marginBottom: 4 }}>
                {result.riskLevel} RISK
              </div>
              <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
                {sector && <span>{sector}: {result.sectorCount} attacks ({result.sectorPercent}% of all recent activity). </span>}
                {country && <span>{countryFlag(country)} {allCountries.find(c => c.code === country)?.name || country}: {result.countryCount} attacks ({result.countryPercent}%). </span>}
                {result.riskScore >= 55
                  ? "Your profile matches a heavily targeted combination. Strong defenses and incident response plans are essential."
                  : result.riskScore >= 30
                  ? "Your profile shows moderate exposure. Standard security practices and monitoring are recommended."
                  : "Your profile shows relatively low current targeting. Maintain baseline security hygiene."}
              </div>
            </div>
          </div>

          {result.topThreats.length > 0 && (
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-secondary)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.8 }}>
                Top Threat Groups to Watch
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {result.topThreats.map((t, i) => (
                  <span key={i} style={{
                    padding: "6px 12px", borderRadius: 6, fontSize: 12, fontWeight: 600,
                    background: i === 0 ? `${result.riskColor}22` : "var(--bg-tertiary)",
                    color: i === 0 ? result.riskColor : "var(--text-secondary)",
                    border: `1px solid ${i === 0 ? result.riskColor + "44" : "var(--border)"}`,
                  }}>
                    {t.name} ({t.count})
                  </span>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginTop: 16, padding: "12px 16px", background: "rgba(255,255,255,0.03)", borderRadius: 8, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--text-secondary)" }}>Recommendations: </strong>
            {result.riskScore >= 55
              ? "Implement EDR solutions, maintain offline backups, conduct regular security audits, establish incident response procedures, and consider cyber insurance. Monitor these threat groups' TTPs closely."
              : result.riskScore >= 30
              ? "Ensure regular backups, keep systems patched, use multi-factor authentication, train employees on phishing awareness, and monitor for suspicious activity."
              : "Maintain regular backups, keep software updated, use strong passwords with MFA, and stay informed about emerging threats in your sector."}
          </div>
        </div>
      )}
    </div>
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
  const [groupSearch, setGroupSearch] = useState("");
  const [copiedIndex, setCopiedIndex] = useState(null);

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

  /* ── filtered groups ── */
  const filteredGroups = useMemo(() => {
    if (!dashboard?.groups_directory) return [];
    if (!groupSearch) return dashboard.groups_directory;
    const q = groupSearch.toLowerCase();
    return dashboard.groups_directory.filter(g =>
      (g.name || "").toLowerCase().includes(q) ||
      (g.description || "").toLowerCase().includes(q)
    );
  }, [dashboard, groupSearch]);

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

      {/* ── NEW: Threat Pulse Score ── */}
      <ThreatPulse dashboard={dashboard} />

      {/* ── NEW: Live Attack Map ── */}
      <AttackMap countries={dashboard?.all_countries || []} />

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
          ["risk", "🛡️ Risk Check"],
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

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {filteredVictims.slice(0, 100).map((v, i) => {
              const tweetTemplates = [
                `${v.group_name} just added ${v.victim}${v.country_name ? ` from ${v.country_name}` : ""} to their leak site.${v.activity && v.activity !== "Not Found" ? ` They're in the ${v.activity} sector.` : ""}\n\nThis is why no organization is too big or too small to be a target.\n\n#Ransomware #CyberSecurity`,
                `Another day, another ransomware hit.\n\n${v.victim}${v.country_name ? ` (${v.country_name})` : ""} appears on ${v.group_name}'s victim list.${v.activity && v.activity !== "Not Found" ? ` Sector: ${v.activity}.` : ""}\n\nStay vigilant, patch your systems, back up your data.\n\n#InfoSec #ThreatIntel`,
                `${v.group_name} has claimed ${v.victim}${v.country_name ? ` in ${v.country_name}` : ""} as their latest victim.${v.activity && v.activity !== "Not Found" ? `\n\nThe ${v.activity} sector continues to be under fire.` : ""}\n\nOrganizations — take ransomware seriously before it's too late.\n\n#CyberSecurity #Ransomware`,
                `Breaking: ${v.victim}${v.country_name ? ` (${v.country_name})` : ""} hit by ${v.group_name} ransomware group.${v.activity && v.activity !== "Not Found" ? `\n\n${v.activity} sector targeted once again.` : ""}\n\nA reminder to review your incident response plans today, not tomorrow.\n\n#Ransomware #InfoSec`,
              ];
              const tweetText = tweetTemplates[i % tweetTemplates.length];
              const isCopied = copiedIndex === i;
              return (
                <div key={i} className="card" style={{ padding: 16, transition: "border-color 0.2s" }}
                  onMouseOver={e => e.currentTarget.style.borderColor = "var(--accent)"}
                  onMouseOut={e => e.currentTarget.style.borderColor = "var(--border)"}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                    {/* Main content */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                        <span onClick={() => { setTab("groups"); loadGroupVictims(v.group_name); }}
                          style={{ padding: "3px 10px", borderRadius: 5, fontSize: 12, fontWeight: 700, background: "rgba(255,61,61,0.15)", color: "var(--accent)", cursor: "pointer", border: "1px solid rgba(255,61,61,0.3)" }}>
                          {v.group_name}
                        </span>
                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>claimed</span>
                        <span className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>{timeAgo(v.discovered)}</span>
                      </div>
                      <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
                        {v.victim}
                      </div>
                      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12 }}>
                        {v.country && (
                          <span onClick={() => { setTab("countries"); loadCountryVictims(v.country); }}
                            style={{ cursor: "pointer", color: "var(--info)" }}>
                            {countryFlag(v.country)} {v.country_name || v.country}
                          </span>
                        )}
                        {v.activity && v.activity !== "Not Found" && (
                          <span style={{ color: "var(--text-secondary)" }}>
                            📁 {v.activity}
                          </span>
                        )}
                        {v.website && (
                          <span style={{ color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200, fontSize: 11 }}>
                            🔗 {v.website}
                          </span>
                        )}
                      </div>
                    </div>
                    {/* Copy Tweet button */}
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(tweetText).then(() => {
                          setCopiedIndex(i);
                          setTimeout(() => setCopiedIndex(null), 2000);
                        });
                      }}
                      style={{
                        padding: "6px 12px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                        border: `1px solid ${isCopied ? "rgba(81,207,102,0.4)" : "var(--border)"}`,
                        background: isCopied ? "rgba(81,207,102,0.1)" : "var(--bg-tertiary)",
                        color: isCopied ? "#51cf66" : "var(--text-secondary)",
                        cursor: "pointer", whiteSpace: "nowrap", transition: "all 0.2s",
                        flexShrink: 0,
                      }}
                    >
                      {isCopied ? "✓ Copied!" : "📋 Copy Tweet"}
                    </button>
                  </div>
                </div>
              );
            })}
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
              <GroupProfile
                groupName={selectedGroup}
                groupVictims={groupVictims}
                groupLoading={groupLoading}
                dashboard={dashboard}
                onCountryClick={(code) => { setTab("countries"); loadCountryVictims(code); }}
              />
              {!groupLoading && groupVictims && (
                <div className="card" style={{ padding: 0, overflow: "hidden", borderTop: "none", borderTopLeftRadius: 0, borderTopRightRadius: 0 }}>
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
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>All Groups Directory ({dashboard?.groups_directory?.length || 0})</div>
              </div>
              <input type="text" placeholder="Search groups by name or description..."
                value={groupSearch} onChange={e => setGroupSearch(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 13, marginBottom: 12, boxSizing: "border-box" }}
              />
              {groupSearch && filteredGroups.length !== (dashboard?.groups_directory?.length || 0) && (
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
                  Showing {filteredGroups.length} of {dashboard?.groups_directory?.length || 0} groups
                </div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
                {filteredGroups.map((g, i) => (
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

      {/* ═══ TAB: Risk Check ═════════════════════════════════════ */}
      {tab === "risk" && <RiskAssessment dashboard={dashboard} />}

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
