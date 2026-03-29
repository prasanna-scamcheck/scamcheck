import React from "react";

export function AboutPage() {
  return (
    <div className="legal-page" style={{ maxWidth: 860 }}>
      {/* Hero Section */}
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div className="hero-badge" style={{ marginBottom: 16 }}>About CyberIntelEngine</div>
        <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: -1, marginBottom: 12 }}>
          India's First Cybercrime Intelligence<br />
          <span style={{ color: "var(--accent)" }}>Search Engine & Scam Playbook Predictor</span>
        </h2>
        <p style={{ color: "var(--text-secondary)", fontSize: 15, maxWidth: 600, margin: "0 auto", lineHeight: 1.7 }}>
          Built to protect Indian citizens from cyber fraud — before they lose their money, not after.
        </p>
      </div>

      {/* Mission */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Our Mission</div>
        <p style={{ fontSize: 15, lineHeight: 1.8, color: "var(--text-secondary)" }}>
          Indians lost over ₹10,000 crore to cyber scams in 2024-2025. Every existing solution is reactive —
          they identify threats after the damage is done. Truecaller tells you "spam" after you pick up.
          cybercrime.gov.in takes reports after you've lost money. Banks block transactions after fraud is detected.
        </p>
        <p style={{ fontSize: 15, lineHeight: 1.8, color: "var(--text-secondary)", marginTop: 12 }}>
          CyberIntelEngine exists to change this. We believe the most effective cybersecurity happens
          <strong style={{ color: "var(--text-primary)" }}> before </strong> the crime, not after. Our platform
          lets citizens search any suspicious phone number, UPI ID, bank account, email, or website and
          get instant intelligence. Our Scam Playbook Predictor shows the complete modus operandi of a scam
          in real-time — so you can see the scammer's script before they read it to you.
        </p>
      </div>

      {/* Platform Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
        {[
          ["2,847+", "Threat Indicators", "var(--accent)"],
          ["10+", "Scam Playbooks", "var(--high-risk)"],
          ["11", "Threat Feeds", "var(--info)"],
          ["24/7", "Live & Free", "var(--safe)"],
        ].map(([num, label, color]) => (
          <div key={label} className="card" style={{ textAlign: "center", padding: 20 }}>
            <div className="mono" style={{ fontSize: 28, fontWeight: 700, color }}>{num}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* What We Do */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">What CyberIntelEngine Does</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {[
            ["🔍", "Intelligence Search", "Search any phone number, UPI ID, bank account, email, domain, or crypto wallet against our database of 2,847+ real threat indicators sourced from global cybercrime feeds."],
            ["🔮", "Scam Playbook Predictor", "Paste any suspicious message — WhatsApp, SMS, email, or call description — and instantly see the complete scam DNA: every step the scammer takes, red flags, money trail, and prevention tips."],
            ["📊", "Risk Scoring", "Every indicator gets a risk score from 0-100 based on complaint count, linked indicators, report frequency, and verified confirmations. Clear categories: Safe, Suspicious, High Risk, Confirmed Fraud."],
            ["🔗", "Linked Intelligence", "If one scam indicator appears in multiple reports, we automatically map the connections — phone to UPI to bank account to domain — revealing entire fraud networks."],
            ["📝", "Community Reporting", "Citizens can report scams through our platform. Every report enters a moderation queue, gets verified, and strengthens the intelligence database for everyone."],
            ["🛡️", "Prevention First", "Unlike reactive tools, CyberIntelEngine is designed to stop fraud before money is transferred. Our tagline says it all: Verify before you trust or pay."],
          ].map(([icon, title, desc]) => (
            <div key={title} style={{ padding: 16, background: "var(--bg-tertiary)", borderRadius: 12, border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>{icon}</div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>{title}</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Founder Section */}
      <div className="card" style={{ marginBottom: 20, borderColor: "rgba(255,61,61,0.2)" }}>
        <div className="card-title">Created & Developed By</div>
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
              Founder & Developer — CyberIntelEngine
            </div>
            <div style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.8, marginBottom: 16 }}>
              A cybersecurity veteran with 30 years of experience, Prasanna currently serves as
              CISO at Red Piranha — an Australian cybersecurity company and member of the Cyber Threat Alliance.
              His career spans threat intelligence, security operations, penetration testing, and building
              enterprise-grade security platforms.
            </div>
            <div style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.8, marginBottom: 16 }}>
              Having witnessed millions of Indians fall victim to preventable cyber scams, Prasanna
              built CyberIntelEngine to bridge the gap between cybersecurity expertise and everyday citizens.
              The platform represents his conviction that the best defense against cybercrime is education
              and awareness at the moment of decision — not after the damage is done.
            </div>

            {/* Credentials */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
              {[
                "30 Years in Cybersecurity",
                "CISO — Red Piranha",
                "Threat Intelligence",
                "Security Operations",
                "XDR & Zero Trust",
                "Cyber Threat Alliance Member",
              ].map(tag => (
                <span key={tag} style={{
                  padding: "4px 12px", borderRadius: 100, fontSize: 11,
                  background: "var(--bg-tertiary)", border: "1px solid var(--border)",
                  color: "var(--text-secondary)", fontWeight: 500
                }}>{tag}</span>
              ))}
            </div>

            <div style={{ fontSize: 13, color: "var(--text-muted)", fontStyle: "italic", lineHeight: 1.6, padding: 16, background: "var(--bg-tertiary)", borderRadius: 10, borderLeft: "3px solid var(--accent)" }}>
              "Every day, thousands of Indians lose their hard-earned money to scams that follow predictable
              patterns. I built CyberIntelEngine because I believe that if you can see the scam coming,
              you can stop it. This platform puts 30 years of cybersecurity knowledge into the hands of
              every citizen — for free."
              <div style={{ marginTop: 8, fontStyle: "normal", fontWeight: 600, color: "var(--text-secondary)" }}>— Prasanna Peshkar</div>
            </div>
          </div>
        </div>
      </div>

      {/* Technology */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Technology & Data Sources</div>
        <p style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.8, marginBottom: 16 }}>
          CyberIntelEngine is built on a modern, production-grade technology stack and sources threat
          intelligence from globally trusted cybersecurity databases.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>Platform</div>
            {["React Frontend", "Python/FastAPI Backend", "Real-time Risk Scoring Engine", "Pattern-based Scam DNA Analyzer", "Moderated Reporting Pipeline"].map(t => (
              <div key={t} style={{ fontSize: 13, color: "var(--text-secondary)", padding: "4px 0" }}>→ {t}</div>
            ))}
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>Intelligence Feeds</div>
            {["URLhaus (abuse.ch)", "PhishTank (Cisco)", "Have I Been Pwned", "OpenPhish", "Feodo Tracker", "SSL Blacklist", "India-specific curated data"].map(t => (
              <div key={t} style={{ fontSize: 13, color: "var(--text-secondary)", padding: "4px 0" }}>→ {t}</div>
            ))}
          </div>
        </div>
      </div>

      {/* Beta Notice */}
      <div className="action-banner" style={{ borderColor: "var(--info)", background: "rgba(59,130,246,0.06)", marginBottom: 20 }}>
        <div className="icon">🚀</div>
        <div className="text">
          <strong>Beta Version</strong>
          CyberIntelEngine is currently in beta. We are actively adding more scam playbooks, expanding our
          threat intelligence feeds, and building partnerships with law enforcement agencies. Your feedback
          and scam reports help make the platform better for everyone.
        </div>
      </div>

      {/* Contact */}
      <div className="card" style={{ textAlign: "center", padding: 32 }}>
        <div className="card-title">Get In Touch</div>
        <p style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: 16, lineHeight: 1.7 }}>
          For partnerships, feedback, media inquiries, or law enforcement collaboration:
        </p>
        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--accent)" }}>
          contact@cyberintelengine.com
        </div>
        <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 12 }}>
          Interested in API integration for your bank or fintech platform? Let's talk.
        </div>
      </div>
    </div>
  );
}
