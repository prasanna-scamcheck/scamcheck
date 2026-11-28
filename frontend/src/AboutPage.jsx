import React from "react";

export function AboutPage() {
  return (
    <div className="legal-page" style={{ maxWidth: 860 }}>
      {/* Hero Section */}
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div className="hero-badge" style={{ marginBottom: 16 }}>About CyberIntelEngine</div>
        <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: -1, marginBottom: 12 }}>
          Cybersecurity Intelligence<br />
          <span style={{ color: "var(--accent)" }}>For Everyone, Not Just Enterprises</span>
        </h2>
        <p style={{ color: "var(--text-secondary)", fontSize: 15, maxWidth: 620, margin: "0 auto", lineHeight: 1.7 }}>
          A free, global threat intelligence platform that tracks ransomware, phishing, data breaches,
          and scam operations in real time. Built so anyone can look up a threat before it becomes a loss.
        </p>
      </div>

      {/* The Problem */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">The Problem</div>
        <p style={{ fontSize: 15, lineHeight: 1.8, color: "var(--text-secondary)" }}>
          Billions of dollars are lost to cyber fraud every year. Ransomware groups publish stolen data
          on leak sites. Phishing pages go live and harvest credentials for hours before anyone takes them down.
          Data breaches expose millions of records, and most people never find out until it is too late.
        </p>
        <p style={{ fontSize: 15, lineHeight: 1.8, color: "var(--text-secondary)", marginTop: 12 }}>
          The intelligence to track all of this exists, but it is scattered across dozens of feeds, databases,
          and platforms that most people will never see. CyberIntelEngine brings it together into one place
          and makes it accessible to anyone with a browser. No login. No paywall. No enterprise sales pitch.
        </p>
      </div>

      {/* Platform Capabilities */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
        {[
          ["6", "Intelligence Modules", "var(--accent)"],
          ["Global", "Coverage", "var(--info)"],
          ["Real-time", "Threat Feeds", "var(--high-risk)"],
          ["Free", "No Login Required", "var(--safe)"],
        ].map(([num, label, color]) => (
          <div key={label} className="card" style={{ textAlign: "center", padding: 20 }}>
            <div className="mono" style={{ fontSize: 28, fontWeight: 700, color }}>{num}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* What It Does */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">What CyberIntelEngine Does</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {[
            ["Threat Search", "Look up any phone number, email, UPI ID, bank account, domain, or crypto wallet against a live threat intelligence database. Each result includes a risk score, complaint history, and linked indicators."],
            ["Scam Predictor", "Paste any suspicious message and the platform breaks down the complete scam playbook: the type of fraud, every step the scammer will take, the red flags, and how money moves through the scheme."],
            ["Ransomware Tracker", "Live feed of ransomware group activity worldwide. Victim claims, group profiles with kill chain analysis mapped to MITRE ATT&CK, country and sector breakdowns, and CISA KEV vulnerability tracking."],
            ["Phishing Tracker", "Aggregated feed of active phishing sites detected across multiple threat intelligence sources. Searchable by brand, domain, hosting country, or IP address. Updated every 30 minutes."],
            ["Breach Radar", "Global data breach catalog covering thousands of known breaches. Search by company, domain, or data type to see what was exposed, when it happened, and how many records were affected."],
            ["Scam Pulse", "Tracks 12 categories of cyber fraud globally, from investment scams and crypto fraud to romance scams and sextortion. Shows which categories are rising, estimated losses, and the methods being used right now."],
          ].map(([title, desc]) => (
            <div key={title} style={{ padding: 16, background: "var(--bg-tertiary)", borderRadius: 12, border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6, color: "var(--text-primary)" }}>{title}</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* How It Works */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">How It Works</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {[
            ["01", "Aggregate", "The platform continuously pulls threat data from multiple intelligence sources, normalizing and deduplicating it into a unified database."],
            ["02", "Analyze", "Every data point is scored, categorized, and cross-referenced. Ransomware victims are mapped to groups and countries. Phishing sites are matched to the brands they impersonate. Breach records are indexed by exposed data types."],
            ["03", "Deliver", "The processed intelligence is served through a clean interface that anyone can use. No cybersecurity background required. Search, browse, or track threats in real time."],
          ].map(([num, title, desc]) => (
            <div key={num} style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
              <div className="mono" style={{
                fontSize: 14, fontWeight: 700, color: "var(--accent)",
                width: 40, height: 40, borderRadius: 10,
                background: "rgba(255,61,61,0.08)", border: "1px solid rgba(255,61,61,0.2)",
                display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
              }}>{num}</div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{title}</div>
                <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Founder Section */}
      <div className="card" style={{ marginBottom: 20, borderColor: "rgba(255,61,61,0.2)" }}>
        <div className="card-title">Built By</div>
        <div style={{ display: "flex", gap: 24, alignItems: "flex-start", flexWrap: "wrap" }}>
          <div style={{
            width: 100, height: 100, borderRadius: 16,
            background: "linear-gradient(135deg, var(--accent), #ff7b7b)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 36, fontWeight: 700, color: "white", flexShrink: 0
          }}>
            PP
          </div>
          <div style={{ flex: 1, minWidth: 250 }}>
            <h3 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4, letterSpacing: -0.5 }}>Prasanna Peshkar</h3>
            <div style={{ fontSize: 14, color: "var(--accent)", fontWeight: 600, marginBottom: 12 }}>
              Founder & Developer
            </div>
            <div style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.8, marginBottom: 16 }}>
              Prasanna works in cybersecurity with a focus on threat intelligence and security operations.
              He built CyberIntelEngine because the tools that track cyber threats were either locked behind
              enterprise paywalls or scattered across too many places for most people to use. The goal was
              simple: take the intelligence that security teams rely on and make it available to everyone,
              for free, in one place.
            </div>

            {/* Tags */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
              {[
                "Threat Intelligence",
                "Security Operations",
                "Platform Engineering",
                "Independent Project",
              ].map(tag => (
                <span key={tag} style={{
                  padding: "4px 12px", borderRadius: 100, fontSize: 11,
                  background: "var(--bg-tertiary)", border: "1px solid var(--border)",
                  color: "var(--text-secondary)", fontWeight: 500
                }}>{tag}</span>
              ))}
            </div>

            <div style={{ fontSize: 13, color: "var(--text-muted)", fontStyle: "italic", lineHeight: 1.6, padding: 16, background: "var(--bg-tertiary)", borderRadius: 10, borderLeft: "3px solid var(--accent)" }}>
              "Most people find out they have been compromised long after the damage is done. I built
              CyberIntelEngine to change that. If the intelligence exists to see a threat coming, it should
              not be locked behind a sales call."
              <div style={{ marginTop: 8, fontStyle: "normal", fontWeight: 600, color: "var(--text-secondary)" }}>Prasanna Peshkar</div>
            </div>
          </div>
        </div>
      </div>

      {/* Open & Evolving */}
      <div className="action-banner" style={{ borderColor: "var(--info)", background: "rgba(59,130,246,0.06)", marginBottom: 20 }}>
        <div className="icon" style={{ fontSize: 28 }}>&#x2699;</div>
        <div className="text">
          <strong>Actively Developed</strong>
          CyberIntelEngine is under active development. New intelligence modules, broader threat coverage,
          and deeper analysis capabilities are being added regularly. If you spot something that could be
          better, reach out.
        </div>
      </div>

      {/* Contact */}
      <div className="card" style={{ textAlign: "center", padding: 32 }}>
        <div className="card-title">Contact</div>
        <p style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: 16, lineHeight: 1.7 }}>
          Feedback, media inquiries, collaboration, or vulnerability reports:
        </p>
        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--accent)" }}>
          contact@cyberintelengine.com
        </div>
      </div>
    </div>
  );
}
