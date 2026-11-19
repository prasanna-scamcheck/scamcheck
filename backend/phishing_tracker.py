"""
Phishing Kit Tracker Module for CyberIntelEngine
Aggregates phishing intelligence from PhishTank, Phishunt.io, and URLhaus
Global coverage, updated every 30 minutes
"""

import httpx
import asyncio
import time
from datetime import datetime, timedelta
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

# ─── Cache layer ────────────────────────────────────────────────────
_cache = {}
PHISH_CACHE_TTL = 1800  # 30 minutes

def _get_cached(key):
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < PHISH_CACHE_TTL:
            return data
    return None

def _set_cached(key, data):
    _cache[key] = (data, time.time())


# ─── Known brand categories (for enrichment) ───────────────────────
BRAND_CATEGORIES = {
    # Banking / Financial
    "paypal": "Banking", "chase": "Banking", "wells fargo": "Banking",
    "bank of america": "Banking", "citibank": "Banking", "hsbc": "Banking",
    "barclays": "Banking", "lloyds": "Banking", "santander": "Banking",
    "bnp paribas": "Banking", "deutsche bank": "Banking", "ing": "Banking",
    "sbi": "Banking", "hdfc": "Banking", "icici": "Banking", "axis bank": "Banking",
    "pnb": "Banking", "kotak": "Banking", "canara": "Banking",
    "commonwealth bank": "Banking", "anz": "Banking", "westpac": "Banking",
    "td bank": "Banking", "rbc": "Banking", "scotiabank": "Banking",
    "credit agricole": "Banking", "societe generale": "Banking",
    "unicredit": "Banking", "intesa": "Banking", "bbva": "Banking",
    "dbs": "Banking", "ocbc": "Banking", "uob": "Banking",
    # Tech
    "microsoft": "Technology", "apple": "Technology", "google": "Technology",
    "amazon": "Technology", "meta": "Technology", "facebook": "Technology",
    "instagram": "Technology", "whatsapp": "Technology", "netflix": "Technology",
    "linkedin": "Technology", "twitter": "Technology", "dropbox": "Technology",
    "adobe": "Technology", "zoom": "Technology", "slack": "Technology",
    "github": "Technology", "yahoo": "Technology", "aol": "Technology",
    "outlook": "Technology", "office 365": "Technology", "icloud": "Technology",
    # Payment / Fintech
    "stripe": "Payment", "square": "Payment", "venmo": "Payment",
    "cash app": "Payment", "zelle": "Payment", "wise": "Payment",
    "revolut": "Payment", "paytm": "Payment", "phonepe": "Payment",
    "gpay": "Payment", "razorpay": "Payment", "coinbase": "Payment",
    "binance": "Payment", "kraken": "Payment",
    # Ecommerce
    "ebay": "Ecommerce", "walmart": "Ecommerce", "target": "Ecommerce",
    "aliexpress": "Ecommerce", "shopify": "Ecommerce", "etsy": "Ecommerce",
    "flipkart": "Ecommerce",
    # Logistics
    "dhl": "Logistics", "fedex": "Logistics", "ups": "Logistics",
    "usps": "Logistics", "royal mail": "Logistics", "australia post": "Logistics",
    "india post": "Logistics", "canada post": "Logistics",
    # Government
    "irs": "Government", "hmrc": "Government", "ato": "Government",
    "aadhaar": "Government", "pan card": "Government", "epfo": "Government",
    "irctc": "Government", "gov.uk": "Government",
    # Telecom
    "at&t": "Telecom", "verizon": "Telecom", "t-mobile": "Telecom",
    "vodafone": "Telecom", "airtel": "Telecom", "jio": "Telecom",
    # Social
    "tiktok": "Social Media", "snapchat": "Social Media", "telegram": "Social Media",
    "discord": "Social Media", "reddit": "Social Media",
}

# Country code to name mapping (abbreviated, for hosting country display)
HOSTING_COUNTRIES = {
    "US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
    "NL": "Netherlands", "FR": "France", "GB": "United Kingdom", "CA": "Canada",
    "SG": "Singapore", "JP": "Japan", "KR": "South Korea", "BR": "Brazil",
    "IN": "India", "AU": "Australia", "UA": "Ukraine", "RO": "Romania",
    "BG": "Bulgaria", "HK": "Hong Kong", "ID": "Indonesia", "VN": "Vietnam",
    "TH": "Thailand", "PH": "Philippines", "MY": "Malaysia", "ZA": "South Africa",
    "PL": "Poland", "CZ": "Czech Republic", "SE": "Sweden", "FI": "Finland",
    "IT": "Italy", "ES": "Spain", "MX": "Mexico", "AR": "Argentina",
    "CO": "Colombia", "CL": "Chile", "TR": "Turkey", "IL": "Israel",
    "AE": "UAE", "SA": "Saudi Arabia", "EG": "Egypt", "NG": "Nigeria",
    "KE": "Kenya", "IE": "Ireland", "CH": "Switzerland", "AT": "Austria",
    "BE": "Belgium", "DK": "Denmark", "NO": "Norway", "PT": "Portugal",
    "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "PA": "Panama",
    "BZ": "Belize", "SC": "Seychelles", "IS": "Iceland",
}


def _categorize_brand(brand_name):
    """Get the category for a brand name."""
    if not brand_name:
        return "Other"
    lower = brand_name.lower().strip()
    for brand, category in BRAND_CATEGORIES.items():
        if brand in lower or lower in brand:
            return category
    return "Other"


def _extract_domain(url):
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return url


def _normalize_phishunt_entry(entry):
    """Normalize a Phishunt.io API response entry."""
    domain = entry.get("domain", "")
    url = entry.get("url", "")
    company = entry.get("company", "") or ""
    country = entry.get("country", "") or ""

    return {
        "source": "phishunt",
        "url": url,
        "domain": domain,
        "target_brand": company.title() if company else "Unknown",
        "target_category": _categorize_brand(company),
        "hosting_country": country.upper(),
        "hosting_country_name": HOSTING_COUNTRIES.get(country.upper(), country),
        "ip_address": entry.get("ip", ""),
        "asn": entry.get("asn", ""),
        "org": entry.get("org", ""),
        "first_seen": entry.get("first_seen", "") or entry.get("date", ""),
        "score": entry.get("score", 0),
        "verdict": entry.get("verdict", ""),
        "status": "online",
    }


def _normalize_phishtank_entry(entry):
    """Normalize a PhishTank JSON feed entry."""
    url = entry.get("url", "")
    target = entry.get("target", "") or ""
    details = entry.get("details", [])
    ip = ""
    country = ""
    if details and len(details) > 0:
        ip = details[0].get("ip_address", "")
        # PhishTank does not include country in its feed directly
        # but includes network info

    return {
        "source": "phishtank",
        "url": url,
        "domain": _extract_domain(url),
        "target_brand": target if target else "Unknown",
        "target_category": _categorize_brand(target),
        "hosting_country": "",
        "hosting_country_name": "",
        "ip_address": ip,
        "asn": "",
        "org": details[0].get("announcing_network", "") if details else "",
        "first_seen": entry.get("submission_time", ""),
        "score": 100 if entry.get("verified") == "yes" else 50,
        "verdict": "verified" if entry.get("verified") == "yes" else "unverified",
        "status": "online" if entry.get("online") == "yes" else "offline",
        "phishtank_id": entry.get("phish_id"),
        "phishtank_url": entry.get("phish_detail_url", ""),
    }


def _normalize_urlhaus_entry(entry):
    """Normalize a URLhaus API response entry."""
    url = entry.get("url", "")
    tags = entry.get("tags", []) or []
    threat = entry.get("threat", "") or ""

    return {
        "source": "urlhaus",
        "url": url,
        "domain": _extract_domain(url),
        "target_brand": "Unknown",
        "target_category": "Malware Distribution",
        "hosting_country": "",
        "hosting_country_name": "",
        "ip_address": "",
        "asn": "",
        "org": "",
        "first_seen": entry.get("date_added", ""),
        "score": 90,
        "verdict": entry.get("url_status", ""),
        "status": entry.get("url_status", "unknown"),
        "threat_type": threat,
        "tags": tags,
    }


# ─── API Fetchers ───────────────────────────────────────────────────

async def _fetch_phishunt(limit=500):
    """Fetch recent phishing domains from Phishunt.io API."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://phishunt.io/api/v1/domains",
                params={"limit": limit},
                headers={"User-Agent": "CyberIntelEngine/1.0 (https://cyberintelengine.com)"},
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                return [_normalize_phishunt_entry(e) for e in results]
    except Exception as e:
        print(f"[PhishTracker] Phishunt fetch error: {e}")
    return []


async def _fetch_phishtank():
    """Fetch verified online phishing URLs from PhishTank data feed."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            # PhishTank JSON can be large; fetch without API key (limited)
            resp = await client.get(
                "https://data.phishtank.com/data/online-valid.json",
                headers={"User-Agent": "CyberIntelEngine/1.0 (https://cyberintelengine.com)"},
            )
            if resp.status_code == 200:
                data = resp.json()
                # Only take the most recent 500 entries (file can be huge)
                if isinstance(data, list):
                    recent = sorted(data, key=lambda x: x.get("submission_time", ""), reverse=True)[:500]
                    return [_normalize_phishtank_entry(e) for e in recent]
    except Exception as e:
        print(f"[PhishTracker] PhishTank fetch error: {e}")
    return []


async def _fetch_urlhaus_recent():
    """Fetch recent malware/phishing URLs from URLhaus API."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"User-Agent": "CyberIntelEngine/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = data.get("urls", [])
                # Filter to only online entries
                online = [u for u in urls if u.get("url_status") == "online"]
                return [_normalize_urlhaus_entry(e) for e in online[:200]]
    except Exception as e:
        print(f"[PhishTracker] URLhaus fetch error: {e}")
    return []


# ─── Core Data Functions ────────────────────────────────────────────

async def get_phishing_feed():
    """Get aggregated phishing feed from all sources."""
    cached = _get_cached("phishing_feed")
    if cached:
        return cached

    # Fetch from all sources in parallel
    phishunt_data, phishtank_data, urlhaus_data = await asyncio.gather(
        _fetch_phishunt(500),
        _fetch_phishtank(),
        _fetch_urlhaus_recent(),
        return_exceptions=True,
    )

    # Handle exceptions from gather
    if isinstance(phishunt_data, Exception):
        print(f"[PhishTracker] Phishunt exception: {phishunt_data}")
        phishunt_data = []
    if isinstance(phishtank_data, Exception):
        print(f"[PhishTracker] PhishTank exception: {phishtank_data}")
        phishtank_data = []
    if isinstance(urlhaus_data, Exception):
        print(f"[PhishTracker] URLhaus exception: {urlhaus_data}")
        urlhaus_data = []

    # Merge and deduplicate by domain
    all_entries = []
    seen_domains = set()

    # Phishunt first (best enrichment data)
    for entry in phishunt_data:
        domain = entry.get("domain", "").lower()
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            all_entries.append(entry)

    # PhishTank second
    for entry in phishtank_data:
        domain = entry.get("domain", "").lower()
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            all_entries.append(entry)

    # URLhaus last (least phishing-specific)
    for entry in urlhaus_data:
        domain = entry.get("domain", "").lower()
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            all_entries.append(entry)

    # Sort by first_seen descending
    all_entries.sort(key=lambda x: x.get("first_seen", ""), reverse=True)

    _set_cached("phishing_feed", all_entries)
    return all_entries


async def get_phishing_stats():
    """Get phishing dashboard statistics."""
    cached = _get_cached("phishing_stats")
    if cached:
        return cached

    feed = await get_phishing_feed()
    if not feed:
        return {"total": 0, "sources": {}, "top_brands": [], "top_categories": [],
                "top_hosting_countries": [], "recent_24h": 0, "online_count": 0}

    # Count by source
    source_counts = Counter(e.get("source", "unknown") for e in feed)

    # Count by brand
    brand_counts = Counter(e.get("target_brand", "Unknown") for e in feed if e.get("target_brand") != "Unknown")

    # Count by category
    category_counts = Counter(e.get("target_category", "Other") for e in feed)

    # Count by hosting country
    country_counts = Counter()
    for e in feed:
        cc = e.get("hosting_country", "")
        if cc:
            name = HOSTING_COUNTRIES.get(cc, cc)
            country_counts[name] += 1

    # Recent 24h count
    now = datetime.utcnow()
    recent_24h = 0
    for e in feed:
        fs = e.get("first_seen", "")
        if fs:
            try:
                dt = datetime.fromisoformat(fs.replace("Z", "+00:00").replace("T", " ").split("+")[0].strip())
                if (now - dt).total_seconds() < 86400:
                    recent_24h += 1
            except Exception:
                pass

    # Online count
    online_count = sum(1 for e in feed if e.get("status") in ("online", "online"))

    stats = {
        "total": len(feed),
        "sources": dict(source_counts),
        "top_brands": [{"brand": b, "count": c} for b, c in brand_counts.most_common(15)],
        "top_categories": [{"category": cat, "count": c} for cat, c in category_counts.most_common(10)],
        "top_hosting_countries": [{"country": co, "count": c} for co, c in country_counts.most_common(15)],
        "recent_24h": recent_24h,
        "online_count": online_count,
        "last_updated": now.isoformat(),
    }

    _set_cached("phishing_stats", stats)
    return stats


async def search_phishing(keyword: str):
    """Search phishing feed by keyword (brand, domain, URL)."""
    feed = await get_phishing_feed()
    keyword_lower = keyword.lower().strip()
    results = []
    for entry in feed:
        if (keyword_lower in (entry.get("url", "").lower()) or
            keyword_lower in (entry.get("domain", "").lower()) or
            keyword_lower in (entry.get("target_brand", "").lower()) or
            keyword_lower in (entry.get("ip_address", "").lower()) or
            keyword_lower in (entry.get("org", "").lower())):
            results.append(entry)
            if len(results) >= 100:
                break
    return results


async def get_phishing_by_brand(brand: str):
    """Get phishing entries targeting a specific brand."""
    feed = await get_phishing_feed()
    brand_lower = brand.lower().strip()
    return [e for e in feed if brand_lower in (e.get("target_brand", "").lower())]


async def get_phishing_by_country(country: str):
    """Get phishing entries hosted in a specific country."""
    feed = await get_phishing_feed()
    country_upper = country.upper().strip()
    return [e for e in feed if e.get("hosting_country", "").upper() == country_upper]


# ─── Route Registration ────────────────────────────────────────────

def register_phishing_routes(app):
    """Register phishing tracker API routes."""

    @app.get("/api/phishing/feed")
    async def api_phishing_feed(limit: int = 100, offset: int = 0):
        feed = await get_phishing_feed()
        return feed[offset:offset + limit]

    @app.get("/api/phishing/stats")
    async def api_phishing_stats():
        return await get_phishing_stats()

    @app.get("/api/phishing/search/{keyword}")
    async def api_phishing_search(keyword: str):
        if len(keyword) > 200:
            return {"error": "Search query too long"}
        return await search_phishing(keyword)

    @app.get("/api/phishing/brand/{brand}")
    async def api_phishing_brand(brand: str):
        results = await get_phishing_by_brand(brand)
        return results[:200]

    @app.get("/api/phishing/country/{country_code}")
    async def api_phishing_country(country_code: str):
        results = await get_phishing_by_country(country_code)
        return results[:200]
