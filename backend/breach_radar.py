"""
Breach Radar Module for CyberIntelEngine
Aggregates data breach intelligence from HaveIBeenPwned and XposedOrNot
Global coverage, cached for 1 hour (breach data changes infrequently)
"""

import httpx
import asyncio
import re
import time
from datetime import datetime, timedelta
from collections import Counter
from typing import Optional


def _strip_html(text):
    """Remove HTML tags from text."""
    if not text:
        return ""
    return re.sub(r"<[^>]+>", "", text).strip()

# ─── Cache layer ────────────────────────────────────────────────────
_cache = {}
BREACH_CACHE_TTL = 3600  # 1 hour (breaches don't change often)

def _get_cached(key):
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < BREACH_CACHE_TTL:
            return data
    return None

def _set_cached(key, data):
    _cache[key] = (data, time.time())


# ─── HIBP breach normalizer ────────────────────────────────────────

def _normalize_hibp_breach(b):
    """Normalize a HaveIBeenPwned breach entry."""
    return {
        "source": "hibp",
        "name": b.get("Name", ""),
        "title": b.get("Title", ""),
        "domain": b.get("Domain", ""),
        "breach_date": b.get("BreachDate", ""),
        "added_date": b.get("AddedDate", ""),
        "modified_date": b.get("ModifiedDate", ""),
        "pwn_count": b.get("PwnCount", 0),
        "description": _strip_html(b.get("Description", "")),
        "data_classes": b.get("DataClasses", []),
        "is_verified": b.get("IsVerified", False),
        "is_sensitive": b.get("IsSensitive", False),
        "is_malware": b.get("IsMalware", False),
        "is_spam_list": b.get("IsSpamList", False),
        "is_stealer_log": b.get("IsStealerLog", False),
        "logo_path": b.get("LogoPath", ""),
    }


def _normalize_xon_breach(b):
    """Normalize an XposedOrNot breach entry."""
    return {
        "source": "xon",
        "name": b.get("breachID", ""),
        "title": b.get("breachID", ""),
        "domain": b.get("domain", ""),
        "breach_date": b.get("breachedDate", ""),
        "added_date": b.get("addedDate", ""),
        "modified_date": "",
        "pwn_count": b.get("exposedRecords", 0),
        "description": b.get("exposureDescription", ""),
        "data_classes": (b.get("exposedData", "") or "").split(";") if b.get("exposedData") else [],
        "is_verified": b.get("verified", False),
        "is_sensitive": b.get("sensitive", False),
        "is_malware": False,
        "is_spam_list": False,
        "is_stealer_log": False,
        "logo_path": "",
        "industry": b.get("industry", ""),
        "password_risk": b.get("passwordRisk", ""),
        "reference_url": b.get("referenceURL", ""),
    }


def _format_count(n):
    """Format large numbers for display."""
    if not n:
        return "0"
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


# ─── API Fetchers ───────────────────────────────────────────────────

async def _fetch_hibp_breaches():
    """Fetch all breaches from HaveIBeenPwned (no API key needed)."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "CyberIntelEngine/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return [_normalize_hibp_breach(b) for b in data]
    except Exception as e:
        print(f"[BreachRadar] HIBP fetch error: {e}")
    return []


async def _fetch_hibp_latest():
    """Fetch the most recently added breach from HIBP."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://haveibeenpwned.com/api/v3/latestBreach",
                headers={"User-Agent": "CyberIntelEngine/1.0"},
            )
            if resp.status_code == 200:
                return _normalize_hibp_breach(resp.json())
    except Exception as e:
        print(f"[BreachRadar] HIBP latest fetch error: {e}")
    return None


async def _fetch_xon_breaches():
    """Fetch all breaches from XposedOrNot (no API key needed)."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://api.xposedornot.com/v1/breaches",
                headers={"User-Agent": "CyberIntelEngine/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get("exposedBreaches", [])
                return [_normalize_xon_breach(b) for b in breaches]
    except Exception as e:
        print(f"[BreachRadar] XposedOrNot fetch error: {e}")
    return []


# ─── Core Data Functions ────────────────────────────────────────────

async def get_breach_catalog():
    """Get merged breach catalog from all sources."""
    cached = _get_cached("breach_catalog")
    if cached:
        return cached

    hibp_data, xon_data = await asyncio.gather(
        _fetch_hibp_breaches(),
        _fetch_xon_breaches(),
        return_exceptions=True,
    )

    if isinstance(hibp_data, Exception):
        print(f"[BreachRadar] HIBP exception: {hibp_data}")
        hibp_data = []
    if isinstance(xon_data, Exception):
        print(f"[BreachRadar] XON exception: {xon_data}")
        xon_data = []

    # Merge: HIBP as primary, XON for enrichment
    all_breaches = []
    seen_names = set()

    # HIBP first (more authoritative)
    for b in hibp_data:
        name_lower = b["name"].lower()
        if name_lower not in seen_names:
            seen_names.add(name_lower)
            # Try to enrich with XON data (industry, password_risk)
            for xb in xon_data:
                if xb["name"].lower() == name_lower or xb.get("domain", "").lower() == b.get("domain", "").lower():
                    b["industry"] = xb.get("industry", "")
                    b["password_risk"] = xb.get("password_risk", "")
                    b["reference_url"] = xb.get("reference_url", "")
                    break
            all_breaches.append(b)

    # XON unique entries
    for b in xon_data:
        name_lower = b["name"].lower()
        if name_lower not in seen_names:
            seen_names.add(name_lower)
            all_breaches.append(b)

    # Sort by added_date descending (most recent first)
    all_breaches.sort(key=lambda x: x.get("added_date", ""), reverse=True)

    _set_cached("breach_catalog", all_breaches)
    return all_breaches


async def get_breach_stats():
    """Get breach dashboard statistics."""
    cached = _get_cached("breach_stats")
    if cached:
        return cached

    catalog = await get_breach_catalog()
    if not catalog:
        return {"total_breaches": 0, "total_records": 0}

    total_records = sum(b.get("pwn_count", 0) for b in catalog)
    verified_count = sum(1 for b in catalog if b.get("is_verified"))

    # Data classes frequency
    data_classes = Counter()
    for b in catalog:
        for dc in b.get("data_classes", []):
            if dc:
                data_classes[dc.strip()] += 1

    # Breaches by year
    year_counts = Counter()
    for b in catalog:
        bd = b.get("breach_date", "")
        if bd and len(bd) >= 4:
            year_counts[bd[:4]] += 1

    # Recent breaches (last 90 days)
    now = datetime.utcnow()
    recent = []
    for b in catalog:
        ad = b.get("added_date", "")
        if ad:
            try:
                dt = datetime.fromisoformat(ad.replace("Z", "+00:00").split("T")[0])
                if (now - dt).days <= 90:
                    recent.append(b)
            except Exception:
                pass

    # Largest breaches
    largest = sorted(catalog, key=lambda x: x.get("pwn_count", 0), reverse=True)[:15]

    # Industry breakdown (from XON enrichment)
    industry_counts = Counter()
    for b in catalog:
        ind = b.get("industry", "")
        if ind:
            industry_counts[ind] += 1

    stats = {
        "total_breaches": len(catalog),
        "total_records": total_records,
        "total_records_formatted": _format_count(total_records),
        "verified_count": verified_count,
        "recent_90d": len(recent),
        "recent_breaches": recent[:20],
        "top_data_classes": [{"name": dc, "count": c} for dc, c in data_classes.most_common(15)],
        "yearly_breakdown": sorted([{"year": y, "count": c} for y, c in year_counts.items()], key=lambda x: x["year"], reverse=True)[:10],
        "largest_breaches": [{"name": b["title"], "domain": b["domain"], "pwn_count": b["pwn_count"], "pwn_count_formatted": _format_count(b["pwn_count"]), "breach_date": b["breach_date"]} for b in largest],
        "top_industries": [{"industry": ind, "count": c} for ind, c in industry_counts.most_common(10)],
        "last_updated": now.isoformat(),
    }

    _set_cached("breach_stats", stats)
    return stats


async def search_breaches(keyword: str):
    """Search breach catalog by keyword."""
    catalog = await get_breach_catalog()
    kw = keyword.lower().strip()
    results = []
    for b in catalog:
        if (kw in b.get("name", "").lower() or
            kw in b.get("title", "").lower() or
            kw in b.get("domain", "").lower() or
            kw in b.get("description", "").lower() or
            kw in b.get("industry", "").lower() or
            any(kw in dc.lower() for dc in b.get("data_classes", []))):
            results.append(b)
            if len(results) >= 100:
                break
    return results


async def get_breach_detail(breach_name: str):
    """Get a single breach by name."""
    catalog = await get_breach_catalog()
    name_lower = breach_name.lower().strip()
    for b in catalog:
        if b["name"].lower() == name_lower:
            return b
    return None


async def search_domain_breaches(domain: str):
    """Find all breaches affecting a specific domain."""
    catalog = await get_breach_catalog()
    domain_lower = domain.lower().strip()
    return [b for b in catalog if domain_lower in b.get("domain", "").lower()]


# ─── Route Registration ────────────────────────────────────────────

def register_breach_routes(app):
    """Register breach radar API routes."""

    @app.get("/api/breaches/catalog")
    async def api_breach_catalog(limit: int = 100, offset: int = 0):
        catalog = await get_breach_catalog()
        return catalog[offset:offset + limit]

    @app.get("/api/breaches/stats")
    async def api_breach_stats():
        return await get_breach_stats()

    @app.get("/api/breaches/search/{keyword}")
    async def api_breach_search(keyword: str):
        if len(keyword) > 200:
            return {"error": "Search query too long"}
        return await search_breaches(keyword)

    @app.get("/api/breaches/detail/{breach_name}")
    async def api_breach_detail(breach_name: str):
        result = await get_breach_detail(breach_name)
        if not result:
            return {"error": "Breach not found"}
        return result

    @app.get("/api/breaches/domain/{domain}")
    async def api_breach_domain(domain: str):
        return await search_domain_breaches(domain)

    @app.get("/api/breaches/latest")
    async def api_breach_latest():
        result = await _fetch_hibp_latest()
        if result:
            return result
        return {"error": "Could not fetch latest breach"}
