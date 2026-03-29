import React from "react";

/* ══════════════════════════════════════════════════════════════════
   PRIVACY POLICY
   ══════════════════════════════════════════════════════════════════ */
export function PrivacyPolicy() {
  return (
    <div className="legal-page">
      <h2>Privacy Policy</h2>
      <p className="legal-date">Last updated: {new Date().toLocaleDateString("en-IN", { year: "numeric", month: "long", day: "numeric" })}</p>

      <div className="legal-content">
        <section>
          <h3>1. Introduction</h3>
          <p>
            CyberIntelEngine ("we", "our", "us") operates a cybercrime intelligence search engine
            designed to help citizens verify whether a phone number, UPI ID, bank account,
            email, or website is linked to cyber fraud. This Privacy Policy explains how we
            collect, use, and protect your information when you use our platform.
          </p>
        </section>

        <section>
          <h3>2. Information We Collect</h3>
          <p><strong>Search Queries:</strong> When you search for an indicator (phone number, UPI ID, etc.),
            we log the search query for analytics and service improvement. We do not associate
            search queries with your personal identity.</p>
          <p><strong>Fraud Reports:</strong> When you submit a scam report, we collect the
            indicator details, scam description, city, and state you provide. We do not
            collect your name, email, or phone number unless you voluntarily include them
            in the description.</p>
          <p><strong>Technical Data:</strong> We automatically collect standard server logs
            including IP address, browser type, and access timestamps. This data is used
            solely for security monitoring and service stability.</p>
        </section>

        <section>
          <h3>3. How We Use Your Information</h3>
          <p>We use the collected information to:</p>
          <p>
            • Operate and maintain the cybercrime intelligence search engine<br />
            • Process and verify fraud reports submitted by users<br />
            • Calculate and update risk scores for reported indicators<br />
            • Generate aggregated fraud trend analytics<br />
            • Improve search accuracy and platform performance<br />
            • Detect and prevent abuse of our reporting system
          </p>
        </section>

        <section>
          <h3>4. Information Sharing</h3>
          <p>
            We do not sell, rent, or trade your personal information. We may share
            aggregated, anonymized fraud intelligence data with law enforcement agencies,
            cybersecurity organizations, and CERTs (Computer Emergency Response Teams)
            to aid in cybercrime prevention. Individual user data is never shared without
            legal requirement.
          </p>
        </section>

        <section>
          <h3>5. Data Sources</h3>
          <p>
            Our intelligence database is populated from publicly available threat intelligence
            feeds, community-submitted reports, and open-source cybersecurity databases.
            See our <strong>Data Sources</strong> page for a full list of intelligence sources and their licenses.
          </p>
        </section>

        <section>
          <h3>6. Data Retention</h3>
          <p>
            Fraud intelligence indicators are retained indefinitely to maintain a comprehensive
            threat database. Server logs are retained for 90 days. Rejected fraud reports
            are deleted within 30 days of rejection.
          </p>
        </section>

        <section>
          <h3>7. Your Rights</h3>
          <p>
            If you believe an indicator associated with you has been incorrectly flagged,
            you may submit a dispute through our Report feature or contact us directly.
            We will review and correct verified errors within 7 business days.
          </p>
        </section>

        <section>
          <h3>8. Security</h3>
          <p>
            We implement industry-standard security measures including input validation,
            SQL injection protection, rate limiting, and encrypted data transmission (HTTPS).
            However, no system is 100% secure, and we cannot guarantee absolute security
            of data transmitted to or from our platform.
          </p>
        </section>

        <section>
          <h3>9. Children's Privacy</h3>
          <p>
            CyberIntelEngine is not directed at children under 13. We do not knowingly collect
            personal information from children.
          </p>
        </section>

        <section>
          <h3>10. Changes to This Policy</h3>
          <p>
            We may update this Privacy Policy from time to time. Changes will be posted
            on this page with an updated revision date. Continued use of CyberIntelEngine after
            changes constitutes acceptance of the revised policy.
          </p>
        </section>

        <section>
          <h3>11. Contact</h3>
          <p>
            For privacy-related inquiries, disputes, or data correction requests,
            contact us at: <span className="accent">privacy@scamcheck.in</span>
          </p>
        </section>
      </div>
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════════
   TERMS OF SERVICE
   ══════════════════════════════════════════════════════════════════ */
export function TermsOfService() {
  return (
    <div className="legal-page">
      <h2>Terms of Service</h2>
      <p className="legal-date">Last updated: {new Date().toLocaleDateString("en-IN", { year: "numeric", month: "long", day: "numeric" })}</p>

      <div className="legal-content">
        <section>
          <h3>1. Acceptance of Terms</h3>
          <p>
            By accessing or using CyberIntelEngine, you agree to be bound by these Terms of Service.
            If you do not agree, you may not use the platform.
          </p>
        </section>

        <section>
          <h3>2. Description of Service</h3>
          <p>
            CyberIntelEngine is a cybercrime intelligence search engine that aggregates publicly
            available threat intelligence data and community-submitted fraud reports.
            The platform allows users to search suspicious identifiers (phone numbers,
            UPI IDs, bank accounts, emails, domains, crypto wallets) and view associated
            risk assessments.
          </p>
        </section>

        <section>
          <h3>3. Disclaimer of Accuracy</h3>
          <p>
            <strong>IMPORTANT:</strong> CyberIntelEngine provides information for reference purposes only.
            We aggregate data from multiple public sources and community reports. We do not
            guarantee the accuracy, completeness, or timeliness of any information displayed
            on the platform.
          </p>
          <p>
            A "Safe" result does not guarantee an indicator is legitimate. A "High Risk"
            result does not constitute legal proof of fraud. Always verify information
            independently and consult official authorities before making financial decisions.
          </p>
        </section>

        <section>
          <h3>4. Not Legal or Financial Advice</h3>
          <p>
            CyberIntelEngine does not provide legal, financial, or law enforcement advice. Our
            risk scores and recommendations are algorithmic assessments based on available
            data and should not be treated as definitive judgments. For legal matters,
            consult a qualified professional. For active fraud, report to
            cybercrime.gov.in or call 1930.
          </p>
        </section>

        <section>
          <h3>5. User Responsibilities</h3>
          <p>When using CyberIntelEngine, you agree to:</p>
          <p>
            • Not submit false or malicious fraud reports<br />
            • Not use the platform to harass, defame, or target individuals<br />
            • Not attempt to manipulate risk scores or game the reporting system<br />
            • Not use automated tools to scrape data without permission<br />
            • Not use the platform for any unlawful purpose<br />
            • Report only information you believe in good faith to be associated with fraud
          </p>
        </section>

        <section>
          <h3>6. Report Submission</h3>
          <p>
            By submitting a fraud report, you confirm that the information provided is
            accurate to the best of your knowledge. False reports submitted with malicious
            intent may result in your access being restricted. All reports are subject to
            moderation and verification before becoming part of the public intelligence
            database.
          </p>
        </section>

        <section>
          <h3>7. Intellectual Property</h3>
          <p>
            The CyberIntelEngine platform, including its design, code, and branding, is our
            intellectual property. Threat intelligence data sourced from third-party
            feeds is subject to their respective licenses (see Data Sources page).
            User-submitted reports become part of the CyberIntelEngine intelligence database
            and may be shared with law enforcement and cybersecurity organizations.
          </p>
        </section>

        <section>
          <h3>8. Limitation of Liability</h3>
          <p>
            CyberIntelEngine is provided "as is" without warranties of any kind. We shall not
            be liable for any direct, indirect, incidental, or consequential damages
            arising from your use of or inability to use the platform. This includes
            but is not limited to financial losses resulting from reliance on information
            displayed on CyberIntelEngine.
          </p>
        </section>

        <section>
          <h3>9. Dispute Resolution for Flagged Indicators</h3>
          <p>
            If you believe a phone number, UPI ID, bank account, email, or domain
            associated with you has been incorrectly flagged on CyberIntelEngine, you may
            submit a dispute with supporting evidence. We will review disputes within
            7 business days and remove or correct entries that are verified to be inaccurate.
          </p>
        </section>

        <section>
          <h3>10. Rate Limiting and Fair Use</h3>
          <p>
            To ensure platform stability, we enforce rate limits on searches and report
            submissions. Excessive automated usage may result in temporary or permanent
            access restrictions.
          </p>
        </section>

        <section>
          <h3>11. Governing Law</h3>
          <p>
            These terms are governed by the laws of India. Any disputes shall be subject
            to the jurisdiction of courts in India.
          </p>
        </section>

        <section>
          <h3>12. Changes to Terms</h3>
          <p>
            We reserve the right to modify these terms at any time. Continued use of
            CyberIntelEngine after modifications constitutes acceptance of the revised terms.
          </p>
        </section>

        <section>
          <h3>13. Contact</h3>
          <p>
            For questions about these terms, contact: <span className="accent">legal@scamcheck.in</span>
          </p>
        </section>
      </div>
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════════
   DATA SOURCES & ATTRIBUTION
   ══════════════════════════════════════════════════════════════════ */
export function DataSources() {
  const sources = [
    {
      name: "URLhaus",
      org: "abuse.ch (Bern University of Applied Sciences)",
      url: "https://urlhaus.abuse.ch",
      data: "Malware distribution URLs and domains",
      license: "CC0 (Public Domain)",
      commercial: true,
    },
    {
      name: "Feodo Tracker",
      org: "abuse.ch",
      url: "https://feodotracker.abuse.ch",
      data: "Banking trojan command & control servers",
      license: "CC0 (Public Domain)",
      commercial: true,
    },
    {
      name: "SSL Blacklist",
      org: "abuse.ch",
      url: "https://sslbl.abuse.ch",
      data: "Malicious SSL certificates and IPs",
      license: "CC0 (Public Domain)",
      commercial: true,
    },
    {
      name: "ThreatFox",
      org: "abuse.ch",
      url: "https://threatfox.abuse.ch",
      data: "Indicators of Compromise (IOCs)",
      license: "CC0 (Public Domain)",
      commercial: true,
    },
    {
      name: "PhishTank",
      org: "OpenDNS / Cisco",
      url: "https://phishtank.org",
      data: "Community-verified phishing URLs",
      license: "Free with attribution",
      commercial: true,
      attribution: "Phishing data provided by PhishTank (phishtank.org)"
    },
    {
      name: "OpenPhish",
      org: "OpenPhish",
      url: "https://openphish.com",
      data: "Phishing URLs detected by automated analysis",
      license: "Community feed — free for non-commercial; check terms for commercial",
      commercial: false,
    },
    {
      name: "Blocklist.de",
      org: "Blocklist.de",
      url: "https://www.blocklist.de",
      data: "IPs reported for brute force, SSH attacks, spam",
      license: "Free for all use",
      commercial: true,
    },
    {
      name: "Have I Been Pwned",
      org: "Troy Hunt",
      url: "https://haveibeenpwned.com",
      data: "Data breach records and breached domain list",
      license: "Public breach list freely available; API has separate terms",
      commercial: true,
    },
    {
      name: "Ransomwatch",
      org: "Josh Highet (open source)",
      url: "https://github.com/joshhighet/ransomwatch",
      data: "Ransomware gang leak site monitoring",
      license: "MIT License",
      commercial: true,
    },
    {
      name: "Disposable Email Domains",
      org: "Community maintained",
      url: "https://github.com/disposable-email-domains/disposable-email-domains",
      data: "List of disposable/temporary email domains",
      license: "MIT License",
      commercial: true,
    },
    {
      name: "Community Reports",
      org: "CyberIntelEngine Users",
      url: null,
      data: "Fraud reports submitted by Indian citizens through CyberIntelEngine",
      license: "CyberIntelEngine proprietary",
      commercial: true,
    },
  ];

  return (
    <div className="legal-page">
      <h2>Data Sources & Attribution</h2>
      <p className="legal-date">Transparency about where our intelligence data comes from</p>

      <div className="legal-content">
        <section>
          <h3>Our Intelligence Sources</h3>
          <p>
            CyberIntelEngine aggregates cybercrime intelligence from multiple trusted, publicly
            available sources maintained by cybersecurity researchers, organizations, and
            the global security community. Below is a complete list of our data sources,
            their providers, and licensing terms.
          </p>
        </section>

        <div className="sources-grid">
          {sources.map((s, i) => (
            <div key={i} className="source-card">
              <div className="source-header">
                <span className="source-name">{s.name}</span>
                <span className={`source-badge ${s.commercial ? "open" : "restricted"}`}>
                  {s.commercial ? "Open Use" : "Check Terms"}
                </span>
              </div>
              <div className="source-org">{s.org}</div>
              <div className="source-data">{s.data}</div>
              <div className="source-license">License: {s.license}</div>
              {s.url && (
                <a href={s.url} target="_blank" rel="noopener noreferrer" className="source-link">
                  {s.url} ↗
                </a>
              )}
              {s.attribution && (
                <div className="source-attribution">Attribution: {s.attribution}</div>
              )}
            </div>
          ))}
        </div>

        <section>
          <h3>Data Accuracy Disclaimer</h3>
          <p>
            While we strive to maintain accurate and up-to-date threat intelligence,
            CyberIntelEngine cannot guarantee the accuracy of data from third-party sources.
            False positives may occur. If you believe an indicator has been incorrectly
            flagged, please submit a dispute through our platform.
          </p>
        </section>

        <section>
          <h3>Update Frequency</h3>
          <p>
            Threat intelligence feeds are updated periodically (every 6 hours by default).
            Community-submitted reports are processed through our moderation queue and
            typically reviewed within 24–48 hours.
          </p>
        </section>

        <section>
          <h3>Acknowledgments</h3>
          <p>
            We extend our gratitude to the cybersecurity research community, particularly
            abuse.ch, PhishTank, Have I Been Pwned, and all open-source contributors
            who make threat intelligence freely available to protect internet users worldwide.
          </p>
          <p>
            Phishing data powered by <a href="https://phishtank.org" target="_blank" rel="noopener noreferrer">PhishTank</a>.
          </p>
        </section>
      </div>
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════════
   DISCLAIMER
   ══════════════════════════════════════════════════════════════════ */
export function Disclaimer() {
  return (
    <div className="legal-page">
      <h2>Disclaimer</h2>
      <p className="legal-date">Please read this carefully before using CyberIntelEngine</p>

      <div className="legal-content">
        <div className="disclaimer-banner">
          <div className="disclaimer-icon">⚠️</div>
          <div>
            <strong>CyberIntelEngine is an informational tool, not a law enforcement or judicial service.</strong>
            <p>
              Results displayed on this platform should be used as one input in your
              decision-making process, not as the sole basis for any action.
            </p>
          </div>
        </div>

        <section>
          <h3>No Guarantee of Accuracy</h3>
          <p>
            CyberIntelEngine aggregates data from publicly available threat intelligence sources
            and community reports. We do not independently verify every data point. False
            positives (legitimate entities incorrectly flagged) and false negatives (fraudulent
            entities not yet reported) are possible.
          </p>
        </section>

        <section>
          <h3>Not a Substitute for Official Channels</h3>
          <p>
            CyberIntelEngine is not affiliated with, endorsed by, or connected to any government
            agency, law enforcement body, or regulatory authority. If you are a victim of
            cybercrime, always report to official channels:
          </p>
          <p>
            • <strong>National Cyber Crime Reporting Portal:</strong> <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a><br />
            • <strong>Cyber Crime Helpline:</strong> 1930<br />
            • <strong>Local Police:</strong> File an FIR at your nearest police station<br />
            • <strong>Bank:</strong> Contact your bank immediately if money was transferred
          </p>
        </section>

        <section>
          <h3>No Legal Judgment</h3>
          <p>
            A risk score or "Confirmed Fraud" label on CyberIntelEngine does not constitute a
            legal finding of guilt or criminal activity. It reflects aggregated reports
            and algorithmic assessment. Only courts of law can determine legal guilt.
          </p>
        </section>

        <section>
          <h3>Limitation of Liability</h3>
          <p>
            Under no circumstances shall CyberIntelEngine, its operators, contributors, or data
            providers be liable for any loss, damage, or harm arising from:
          </p>
          <p>
            • Reliance on information displayed on this platform<br />
            • Financial losses from transactions made based on CyberIntelEngine results<br />
            • Incorrectly flagged indicators (false positives)<br />
            • Indicators not yet in our database (false negatives)<br />
            • Actions taken or not taken based on our risk assessments
          </p>
        </section>

        <section>
          <h3>User Responsibility</h3>
          <p>
            You are solely responsible for your decisions regarding financial transactions,
            sharing of personal information, and interactions with entities you search on
            CyberIntelEngine. We strongly recommend verifying all information through multiple
            independent sources before making any financial decisions.
          </p>
        </section>

        <section>
          <h3>Dispute Process</h3>
          <p>
            If you or your organization has been incorrectly flagged on CyberIntelEngine, you
            have the right to dispute the listing. Contact <span className="accent">disputes@scamcheck.in</span> with
            supporting documentation. We commit to reviewing all disputes within 7
            business days.
          </p>
        </section>
      </div>
    </div>
  );
}
