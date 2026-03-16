"""
ScamCheck — Dark Web & Breach Intelligence Module
Integrates open-source dark web monitoring and breach detection.

Sources:
1. Have I Been Pwned (HIBP)  — Checks if emails appear in data breaches
2. Ahmia.fi                  — Tor .onion search engine (indexes dark web)
3. Ransomwatch               — Tracks ransomware gang leak sites
4. LeakIX                    — Exposed services & leaked databases
5. Paste Monitoring           — Checks paste sites for leaked credentials
6. IntelligenceX (free tier) — Dark web, paste, breach search

Setup:
  - HIBP requires a free API key: https://haveibeenpwned.com/API/Key
  - IntelligenceX free key: https://intelx.io/signup
  - Others work without API keys

Run:  py -3.12 darkweb_monitor.py

Add your API keys in the CONFIG section below or set as environment variables.
"""

import json
import os
import re
import time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
from models import create_tables, SessionLocal, Indicator
from risk_engine import normalize_indicator, calculate_risk_score


# ══════════════════════════════════════════════════════════════════
# CONFIG — Add your API keys here
# ══════════════════════════════════════════════════════════════════

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")  # Get free key at https://haveibeenpwned.com/API/Key
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")  # Get free key at https://intelx.io/signup
LEAKIX_API_KEY = os.getenv("LEAKIX_API_KEY", "")  # Optional: https://leakix.net

# ══════════════════════════════════════════════════════════════════


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def fetch_url(url, headers=None, timeout=30):
    try:
        req = Request(url, headers=headers or {"User-Agent": "ScamCheck/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except URLError as e:
        log(f"  ✗ Failed: {e}")
        return None
    except Exception as e:
        log(f"  ✗ Error: {e}")
        return None


def fetch_json(url, headers=None, timeout=30):
    data = fetch_url(url, headers, timeout)
    if data:
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None
    return None


def add_indicator(db, ref_prefix, counter, ind_type, value, category, notes="", risk_base=50):
    normalized = normalize_indicator(value)
    existing = db.query(Indicator).filter(
        Indicator.normalized_value == normalized
    ).first()

    if existing:
        existing.complaint_count += 1
        existing.last_seen = datetime.utcnow()
        existing.risk_score = min(100, existing.risk_score + 2)
        return counter, False

    ref_id = f"{ref_prefix}-{counter:05d}"
    score = min(100, max(calculate_risk_score(
        complaint_count=1, indicator_type=ind_type, linked_count=0
    ), risk_base))

    ind = Indicator(
        ref_id=ref_id, type=ind_type, value=value[:500],
        normalized_value=normalized[:500], risk_score=score,
        complaint_count=1, category=category, location="Dark Web / Global",
        status="active",
        notes=(notes[:1000] if notes else "Imported from dark web intelligence feed."),
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
    )
    db.add(ind)
    return counter + 1, True


# ══════════════════════════════════════════════════════════════════
# SOURCE 1: Ransomware Leak Site Monitoring (ransomwatch)
# Open source, no API key needed
# Tracks 100+ ransomware gang leak sites on Tor
# GitHub: https://github.com/joshhighet/ransomwatch
# ══════════════════════════════════════════════════════════════════

def fetch_ransomwatch(db, limit=300):
    log("🕸️  Fetching Ransomwatch (ransomware gang leak sites)...")

    # Ransomwatch publishes JSON data on GitHub
    groups_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    data = fetch_json(groups_url)

    if not data:
        log("  ✗ Ransomwatch data unavailable")
        return 0

    count = 0
    counter = 1
    seen_domains = set()

    for post in data:
        group_name = post.get("group_name", "Unknown")
        post_title = post.get("post_title", "")
        discovered = post.get("discovered", "")

        # Extract domains/company names from leak posts
        # These are VICTIMS listed on ransomware gang sites
        if post_title:
            # Look for domain patterns in post titles
            domain_matches = re.findall(
                r'([a-zA-Z0-9-]+\.(com|org|net|in|co|io|gov|edu|biz|info))',
                post_title
            )
            for domain, _ in domain_matches:
                domain = domain.lower()
                if domain in seen_domains or len(domain) < 5:
                    continue
                seen_domains.add(domain)

                counter, added = add_indicator(
                    db, "RW", counter, "domain", domain,
                    category="Ransomware Victim",
                    notes=f"Listed on {group_name} ransomware leak site. "
                          f"Organization may have been breached and data leaked on dark web. "
                          f"Discovered: {discovered}. Source: Ransomwatch.",
                    risk_base=60
                )
                if added:
                    count += 1
                if count >= limit:
                    break

        if count >= limit:
            break

    db.commit()
    log(f"  ✓ Ransomwatch: Added {count} ransomware-related domains")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 2: Ahmia.fi — Dark Web Search Engine
# Indexes .onion sites, provides search API
# No API key needed for basic searches
# ══════════════════════════════════════════════════════════════════

def fetch_ahmia_scam_sites(db, limit=200):
    log("🕸️  Fetching Ahmia.fi (dark web scam sites)...")

    # Search for common Indian scam terms on dark web
    search_terms = [
        "india bank account sell",
        "upi fraud",
        "india credit card dump",
        "aadhaar data",
        "pan card database",
        "india kyc bypass",
        "india sim card clone",
        "paytm hack",
        "phonepe fraud",
        "indian bank login",
    ]

    count = 0
    counter = 1

    for term in search_terms:
        url = f"https://ahmia.fi/search/?q={term.replace(' ', '+')}"
        data = fetch_url(url, headers={"User-Agent": "ScamCheck/1.0 (threat-research)"})

        if not data:
            continue

        # Extract .onion URLs from results
        onion_matches = re.findall(r'([a-z2-7]{16,56}\.onion)', data)
        for onion in set(onion_matches):
            counter, added = add_indicator(
                db, "AH", counter, "domain", onion,
                category="Dark Web Market",
                notes=f"Dark web .onion site found via Ahmia.fi search for '{term}'. "
                      f"Site may be selling stolen Indian financial data or fraud tools. "
                      f"Source: Ahmia.fi dark web index.",
                risk_base=80
            )
            if added:
                count += 1
            if count >= limit:
                break

        # Extract clearnet domains mentioned in dark web context
        domain_matches = re.findall(
            r'(?:target|hack|breach|leak|dump)[^\n]*?([a-zA-Z0-9-]+\.(?:com|in|org|net))',
            data, re.IGNORECASE
        )
        for domain in set(domain_matches):
            domain = domain.lower()
            if len(domain) < 5:
                continue
            counter, added = add_indicator(
                db, "AH", counter, "domain", domain,
                category="Dark Web Reference",
                notes=f"Domain referenced in dark web context (search: '{term}'). "
                      f"May indicate data breach or targeted fraud. Source: Ahmia.fi.",
                risk_base=55
            )
            if added:
                count += 1
            if count >= limit:
                break

        if count >= limit:
            break
        time.sleep(2)  # Rate limiting

    db.commit()
    log(f"  ✓ Ahmia.fi: Added {count} dark web indicators")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 3: Have I Been Pwned — Breach Database
# Checks recently breached domains
# API key required (free for individual use)
# https://haveibeenpwned.com/API/Key
# ══════════════════════════════════════════════════════════════════

def fetch_hibp_breaches(db, limit=200):
    log("🕸️  Fetching Have I Been Pwned (breach data)...")

    if not HIBP_API_KEY:
        log("  ⚠ No HIBP API key set. Get one free at https://haveibeenpwned.com/API/Key")
        log("  ⚠ Set it: set HIBP_API_KEY=your-key-here (Windows)")
        log("  Skipping HIBP, using public breach list instead...")

        # Fallback: Use HIBP's public breach list (no API key needed)
        url = "https://haveibeenpwned.com/api/v3/breaches"
        data = fetch_json(url, headers={
            "User-Agent": "ScamCheck/1.0",
        })

        if not data:
            log("  ✗ HIBP public API unavailable")
            return 0

        count = 0
        counter = 1
        for breach in data[:limit]:
            domain = breach.get("Domain", "")
            name = breach.get("Name", "")
            breach_date = breach.get("BreachDate", "")
            pwn_count = breach.get("PwnCount", 0)
            description = breach.get("Description", "")
            data_classes = ", ".join(breach.get("DataClasses", []))
            is_verified = breach.get("IsVerified", False)

            if not domain or len(domain) < 4:
                continue

            risk = 70 if is_verified else 50
            if pwn_count > 1000000:
                risk += 15
            elif pwn_count > 100000:
                risk += 10

            # Clean HTML from description
            clean_desc = re.sub(r'<[^>]+>', '', description)[:300]

            counter, added = add_indicator(
                db, "HB", counter, "domain", domain,
                category="Data Breach",
                notes=f"Breached on {breach_date}. Records exposed: {pwn_count:,}. "
                      f"Data leaked: {data_classes}. "
                      f"{'Verified breach.' if is_verified else 'Unverified.'} "
                      f"{clean_desc} Source: Have I Been Pwned.",
                risk_base=min(95, risk)
            )
            if added:
                count += 1

        db.commit()
        log(f"  ✓ HIBP: Added {count} breached domains")
        return count

    # With API key — can do email lookups
    # For bulk import, we use the breaches endpoint
    url = "https://haveibeenpwned.com/api/v3/breaches"
    data = fetch_json(url, headers={
        "User-Agent": "ScamCheck/1.0",
        "hibp-api-key": HIBP_API_KEY,
    })

    if not data:
        return 0

    count = 0
    counter = 1
    for breach in data[:limit]:
        domain = breach.get("Domain", "")
        if not domain:
            continue

        breach_date = breach.get("BreachDate", "")
        pwn_count = breach.get("PwnCount", 0)
        data_classes = ", ".join(breach.get("DataClasses", []))

        counter, added = add_indicator(
            db, "HB", counter, "domain", domain,
            category="Data Breach",
            notes=f"Data breach on {breach_date}. {pwn_count:,} accounts exposed. "
                  f"Leaked data: {data_classes}. Source: Have I Been Pwned.",
            risk_base=65
        )
        if added:
            count += 1

    db.commit()
    log(f"  ✓ HIBP: Added {count} breached domains")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 4: Feodo Tracker (abuse.ch) — Banking Trojan C2 Servers
# Tracks botnet command & control servers used for banking fraud
# Free, no API key needed
# ══════════════════════════════════════════════════════════════════

def fetch_feodo_tracker(db, limit=300):
    log("🕸️  Fetching Feodo Tracker (banking trojan C2 servers)...")

    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    data = fetch_url(url)

    if not data:
        log("  ✗ Feodo Tracker unavailable")
        return 0

    count = 0
    counter = 1
    for line in data.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        ip = line.split(",")[0].strip() if "," in line else line

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            counter, added = add_indicator(
                db, "FD", counter, "domain", ip,
                category="Banking Trojan C2",
                notes=f"Command & Control server for banking trojans (Dridex, Emotet, TrickBot, QakBot). "
                      f"Used to steal banking credentials and facilitate financial fraud. "
                      f"Source: Feodo Tracker (abuse.ch).",
                risk_base=85
            )
            if added:
                count += 1
            if count >= limit:
                break

    db.commit()
    log(f"  ✓ Feodo Tracker: Added {count} banking trojan C2 IPs")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 5: SSL Blacklist (abuse.ch) — Malicious SSL Certificates
# Identifies fraudulent HTTPS sites using bad certificates
# Free, no API key needed
# ══════════════════════════════════════════════════════════════════

def fetch_sslbl(db, limit=300):
    log("🕸️  Fetching SSL Blacklist (malicious certificates)...")

    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
    data = fetch_url(url)

    if not data:
        log("  ✗ SSL Blacklist unavailable")
        return 0

    count = 0
    counter = 1
    for line in data.strip().split("\n"):
        if line.startswith("#") or not line.strip():
            continue

        parts = line.split(",")
        if len(parts) >= 3:
            timestamp = parts[0].strip()
            ip = parts[1].strip()
            port = parts[2].strip() if len(parts) > 2 else ""

            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                counter, added = add_indicator(
                    db, "SB", counter, "domain", ip,
                    category="Malicious SSL",
                    notes=f"Server using malicious/fraudulent SSL certificate. "
                          f"Port: {port}. Detected: {timestamp}. "
                          f"Often used for phishing sites with fake HTTPS padlock. "
                          f"Source: SSL Blacklist (abuse.ch).",
                    risk_base=70
                )
                if added:
                    count += 1
                if count >= limit:
                    break

    db.commit()
    log(f"  ✓ SSL Blacklist: Added {count} malicious SSL IPs")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 6: Disposable Email Domains
# Domains used by scammers to create throwaway emails
# ══════════════════════════════════════════════════════════════════

def fetch_disposable_emails(db, limit=500):
    log("🕸️  Fetching disposable email domain list...")

    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    data = fetch_url(url)

    if not data:
        log("  ✗ Disposable email list unavailable")
        return 0

    count = 0
    counter = 1
    for line in data.strip().split("\n"):
        domain = line.strip().lower()
        if not domain or domain.startswith("#") or len(domain) < 4:
            continue

        counter, added = add_indicator(
            db, "DE", counter, "domain", domain,
            category="Disposable Email Service",
            notes=f"Disposable/temporary email domain. Frequently used by scammers "
                  f"to create untraceable email addresses for fraud operations. "
                  f"Emails from this domain should be treated with suspicion.",
            risk_base=40
        )
        if added:
            count += 1
        if count >= limit:
            break

    db.commit()
    log(f"  ✓ Disposable emails: Added {count} domains")
    return count


# ══════════════════════════════════════════════════════════════════
# SOURCE 7: IntelligenceX — Dark Web, Paste, Breach Search
# Free tier: 10,000 requests/month
# https://intelx.io/signup
# ══════════════════════════════════════════════════════════════════

def fetch_intelx(db, limit=100):
    log("🕸️  Fetching IntelligenceX (dark web search)...")

    if not INTELX_API_KEY:
        log("  ⚠ No IntelligenceX API key. Get free tier at https://intelx.io/signup")
        log("  ⚠ Set it: set INTELX_API_KEY=your-key-here")
        log("  Skipping IntelligenceX.")
        return 0

    # Search for Indian fraud-related terms on dark web
    search_terms = ["india upi fraud", "indian bank account", "aadhaar dump"]
    count = 0
    counter = 1

    for term in search_terms:
        import urllib.request
        search_data = json.dumps({
            "term": term,
            "maxresults": 50,
            "media": 0,
            "sort": 2,  # Sort by date
            "terminate": [2]  # Darknet only
        }).encode()

        req = urllib.request.Request(
            f"https://2.intelx.io/intelligent/search",
            data=search_data,
            headers={
                "x-key": INTELX_API_KEY,
                "Content-Type": "application/json",
                "User-Agent": "ScamCheck/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                search_id = result.get("id", "")

            if search_id:
                time.sleep(3)  # Wait for results
                result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=50"
                req2 = urllib.request.Request(result_url, headers={
                    "x-key": INTELX_API_KEY, "User-Agent": "ScamCheck/1.0"
                })
                with urllib.request.urlopen(req2, timeout=30) as resp2:
                    results = json.loads(resp2.read().decode())

                for record in results.get("records", []):
                    name = record.get("name", "")
                    # Extract domains/emails from results
                    domains = re.findall(r'([a-zA-Z0-9-]+\.(?:com|in|org|net|onion))', name)
                    for domain in domains:
                        counter, added = add_indicator(
                            db, "IX", counter, "domain", domain.lower(),
                            category="Dark Web Intelligence",
                            notes=f"Found on dark web via IntelligenceX. "
                                  f"Search context: '{term}'. "
                                  f"Source: IntelligenceX dark web index.",
                            risk_base=70
                        )
                        if added:
                            count += 1
                        if count >= limit:
                            break
        except Exception as e:
            log(f"  ✗ IntelX search failed for '{term}': {e}")
            continue

        if count >= limit:
            break
        time.sleep(2)

    db.commit()
    log(f"  ✓ IntelligenceX: Added {count} dark web indicators")
    return count


# ══════════════════════════════════════════════════════════════════
# MAIN: Run all dark web feeds
# ══════════════════════════════════════════════════════════════════

def run_darkweb_feeds():
    """Run all dark web and breach intelligence feeds."""
    create_tables()
    db = SessionLocal()

    log("=" * 60)
    log("ScamCheck — Dark Web & Breach Intelligence Importer")
    log("=" * 60)
    log("")
    log("FREE SOURCES (no API key needed):")
    log("  • Ransomwatch — Ransomware gang leak sites")
    log("  • Ahmia.fi — Dark web .onion search")
    log("  • Feodo Tracker — Banking trojan C2 servers")
    log("  • SSL Blacklist — Malicious SSL certificates")
    log("  • Disposable emails — Scammer email domains")
    log("  • HIBP (public) — Data breach database")
    log("")
    log("API KEY SOURCES (optional, more data):")
    log(f"  • HIBP API key:    {'✓ SET' if HIBP_API_KEY else '✗ NOT SET'}")
    log(f"  • IntelX API key:  {'✓ SET' if INTELX_API_KEY else '✗ NOT SET'}")
    log("")

    total = 0
    feeds = [
        ("Ransomwatch", fetch_ransomwatch),
        ("Ahmia.fi", fetch_ahmia_scam_sites),
        ("HIBP Breaches", fetch_hibp_breaches),
        ("Feodo Tracker", fetch_feodo_tracker),
        ("SSL Blacklist", fetch_sslbl),
        ("Disposable Emails", fetch_disposable_emails),
        ("IntelligenceX", fetch_intelx),
    ]

    for name, func in feeds:
        try:
            count = func(db)
            total += count
        except Exception as e:
            log(f"  ✗ {name} failed: {e}")
            continue

    log("")
    log("=" * 60)
    log(f"✅ DARK WEB IMPORT COMPLETE: {total} indicators imported")
    log(f"📊 Database now has {db.query(Indicator).count()} total indicators")
    log("=" * 60)
    log("")
    log("💡 To unlock more data, set API keys:")
    log("   set HIBP_API_KEY=your-key    (free at haveibeenpwned.com/API/Key)")
    log("   set INTELX_API_KEY=your-key  (free at intelx.io/signup)")

    db.close()


if __name__ == "__main__":
    run_darkweb_feeds()
