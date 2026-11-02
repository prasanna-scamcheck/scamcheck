"""
Ransomware Tracker Module for CyberIntelEngine
Pulls data from ransomware.live API (v2) and RansomLook API
Global coverage — all countries worldwide
"""

import httpx
import asyncio
import json
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Optional

# ─── Cache layer ────────────────────────────────────────────────────
_cache = {}
CACHE_TTL = 900  # 15 minutes

def _get_cached(key):
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return data
    return None

def _set_cached(key, data):
    _cache[key] = (data, time.time())


# ─── Country name mapping (full global) ─────────────────────────────

COUNTRY_NAMES = {
    "AF":"Afghanistan","AL":"Albania","DZ":"Algeria","AD":"Andorra","AO":"Angola",
    "AG":"Antigua and Barbuda","AR":"Argentina","AM":"Armenia","AU":"Australia",
    "AT":"Austria","AZ":"Azerbaijan","BS":"Bahamas","BH":"Bahrain","BD":"Bangladesh",
    "BB":"Barbados","BY":"Belarus","BE":"Belgium","BZ":"Belize","BJ":"Benin",
    "BT":"Bhutan","BO":"Bolivia","BA":"Bosnia and Herzegovina","BW":"Botswana",
    "BR":"Brazil","BN":"Brunei","BG":"Bulgaria","BF":"Burkina Faso","BI":"Burundi",
    "KH":"Cambodia","CM":"Cameroon","CA":"Canada","CV":"Cape Verde","CF":"Central African Republic",
    "TD":"Chad","CL":"Chile","CN":"China","CO":"Colombia","KM":"Comoros",
    "CG":"Congo","CD":"DR Congo","CR":"Costa Rica","CI":"Ivory Coast","HR":"Croatia",
    "CU":"Cuba","CY":"Cyprus","CZ":"Czech Republic","DK":"Denmark","DJ":"Djibouti",
    "DM":"Dominica","DO":"Dominican Republic","EC":"Ecuador","EG":"Egypt",
    "SV":"El Salvador","GQ":"Equatorial Guinea","ER":"Eritrea","EE":"Estonia",
    "SZ":"Eswatini","ET":"Ethiopia","FJ":"Fiji","FI":"Finland","FR":"France",
    "GA":"Gabon","GM":"Gambia","GE":"Georgia","DE":"Germany","GH":"Ghana",
    "GR":"Greece","GD":"Grenada","GT":"Guatemala","GN":"Guinea","GW":"Guinea-Bissau",
    "GY":"Guyana","HT":"Haiti","HN":"Honduras","HU":"Hungary","IS":"Iceland",
    "IN":"India","ID":"Indonesia","IR":"Iran","IQ":"Iraq","IE":"Ireland",
    "IL":"Israel","IT":"Italy","JM":"Jamaica","JP":"Japan","JO":"Jordan",
    "KZ":"Kazakhstan","KE":"Kenya","KI":"Kiribati","KP":"North Korea","KR":"South Korea",
    "KW":"Kuwait","KG":"Kyrgyzstan","LA":"Laos","LV":"Latvia","LB":"Lebanon",
    "LS":"Lesotho","LR":"Liberia","LY":"Libya","LI":"Liechtenstein","LT":"Lithuania",
    "LU":"Luxembourg","MG":"Madagascar","MW":"Malawi","MY":"Malaysia","MV":"Maldives",
    "ML":"Mali","MT":"Malta","MH":"Marshall Islands","MR":"Mauritania","MU":"Mauritius",
    "MX":"Mexico","FM":"Micronesia","MD":"Moldova","MC":"Monaco","MN":"Mongolia",
    "ME":"Montenegro","MA":"Morocco","MZ":"Mozambique","MM":"Myanmar","NA":"Namibia",
    "NR":"Nauru","NP":"Nepal","NL":"Netherlands","NZ":"New Zealand","NI":"Nicaragua",
    "NE":"Niger","NG":"Nigeria","MK":"North Macedonia","NO":"Norway","OM":"Oman",
    "PK":"Pakistan","PW":"Palau","PS":"Palestine","PA":"Panama","PG":"Papua New Guinea",
    "PY":"Paraguay","PE":"Peru","PH":"Philippines","PL":"Poland","PT":"Portugal",
    "QA":"Qatar","RO":"Romania","RU":"Russia","RW":"Rwanda","KN":"Saint Kitts and Nevis",
    "LC":"Saint Lucia","VC":"Saint Vincent","WS":"Samoa","SM":"San Marino",
    "ST":"Sao Tome and Principe","SA":"Saudi Arabia","SN":"Senegal","RS":"Serbia",
    "SC":"Seychelles","SL":"Sierra Leone","SG":"Singapore","SK":"Slovakia",
    "SI":"Slovenia","SB":"Solomon Islands","SO":"Somalia","ZA":"South Africa",
    "SS":"South Sudan","ES":"Spain","LK":"Sri Lanka","SD":"Sudan","SR":"Suriname",
    "SE":"Sweden","CH":"Switzerland","SY":"Syria","TW":"Taiwan","TJ":"Tajikistan",
    "TZ":"Tanzania","TH":"Thailand","TL":"Timor-Leste","TG":"Togo","TO":"Tonga",
    "TT":"Trinidad and Tobago","TN":"Tunisia","TR":"Turkey","TM":"Turkmenistan",
    "TV":"Tuvalu","UG":"Uganda","UA":"Ukraine","AE":"UAE","GB":"United Kingdom",
    "US":"United States","UY":"Uruguay","UZ":"Uzbekistan","VU":"Vanuatu",
    "VA":"Vatican City","VE":"Venezuela","VN":"Vietnam","YE":"Yemen","ZM":"Zambia",
    "ZW":"Zimbabwe","HK":"Hong Kong","MO":"Macau","PR":"Puerto Rico","XK":"Kosovo",
}


# ─── API clients ────────────────────────────────────────────────────

RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2"
RANSOMLOOK_BASE = "https://www.ransomlook.io/api"

HEADERS = {
    "User-Agent": "CyberIntelEngine/1.0 (Threat Intelligence Platform)",
    "Accept": "application/json",
}

async def _fetch_json(url: str, timeout: float = 30.0):
    """Fetch JSON from an external API with error handling."""
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=HEADERS, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 429:
                return {"error": "rate_limited", "message": "API rate limit reached. Try again in a few minutes."}
            if resp.status_code != 200:
                return {"error": "api_error", "message": f"API returned status {resp.status_code}"}
            return resp.json()
    except httpx.TimeoutException:
        return {"error": "timeout", "message": "API request timed out"}
    except Exception as e:
        return {"error": "connection_error", "message": str(e)}


# ─── Normalize victim record ───────────────────────────────────────

def _normalize_victim(v, fallback_group="Unknown"):
    # Extract data size — API may return it as string like "200 GB" or number
    data_size = v.get("data_size") or v.get("dataSize") or v.get("data_exfiltrated", "")
    if isinstance(data_size, (int, float)):
        data_size = f"{data_size} GB"

    return {
        "group_name": v.get("group_name") or v.get("group", fallback_group),
        "victim": v.get("victim") or v.get("post_title", "Unknown"),
        "website": v.get("website", ""),
        "discovered": v.get("discovered") or v.get("published", ""),
        "country": v.get("country", ""),
        "country_name": COUNTRY_NAMES.get((v.get("country") or "").upper(), v.get("country", "")),
        "activity": v.get("activity") or v.get("sector", ""),
        "description": v.get("description", ""),
        # Enriched fields
        "post_url": v.get("post_url") or v.get("claim_url") or v.get("claimUrl", ""),
        "attack_date": v.get("attackdate") or v.get("attackDate") or v.get("attack_date", ""),
        "data_size": str(data_size) if data_size else "",
        "infostealer": v.get("infostealer", ""),
        "screenshot": v.get("screenshot", ""),
        "url": v.get("url", ""),  # ransomware.live permalink
    }


# ─── Data fetchers ──────────────────────────────────────────────────

async def get_recent_victims(limit: int = 0):
    """Get recent ransomware victims from ransomware.live. limit=0 means all."""
    cached = _get_cached("recent_victims")
    if cached:
        return cached[:limit] if limit > 0 else cached

    all_victims = []
    seen = set()  # deduplicate by (group_name, victim, discovered)
    now = datetime.utcnow()

    # Step 1: Fetch /recentvictims for the freshest data (latest 100)
    recent_data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/recentvictims")
    if isinstance(recent_data, list):
        for v in recent_data:
            key = (v.get("group_name", ""), v.get("victim", ""), v.get("discovered", ""))
            if key not in seen:
                seen.add(key)
                all_victims.append(v)

    # Step 2: Fetch by month for full history (current + last 5 months)
    for months_ago in range(6):
        dt = now - timedelta(days=months_ago * 30)
        year = dt.year
        month = dt.month
        url = f"{RANSOMWARE_LIVE_BASE}/victims/{year}/{month}"
        data = await _fetch_json(url, timeout=45.0)

        if isinstance(data, dict) and "error" in data:
            continue  # skip failed months, try the rest

        if isinstance(data, list):
            for v in data:
                key = (v.get("group_name", ""), v.get("victim", ""), v.get("discovered", ""))
                if key not in seen:
                    seen.add(key)
                    all_victims.append(v)

    # Sort by discovered date, newest first
    all_victims.sort(key=lambda v: v.get("discovered", ""), reverse=True)

    victims = [_normalize_victim(v) for v in all_victims]
    _set_cached("recent_victims", victims)
    return victims[:limit] if limit > 0 else victims


async def get_all_groups():
    """Get all ransomware groups from ransomware.live."""
    cached = _get_cached("all_groups")
    if cached:
        return cached

    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/groups")
    if isinstance(data, dict) and "error" in data:
        return data

    groups = []
    if isinstance(data, list):
        for g in data:
            groups.append({
                "name": g.get("name") or g.get("group_name", "Unknown"),
                "description": g.get("description", ""),
                "url": g.get("url") or g.get("website", ""),
                "locations": g.get("locations") or [],
                "profile": g.get("profile", []),
                "meta": g.get("meta", ""),
            })

    _set_cached("all_groups", groups)
    return groups


async def get_group_detail(group_name: str):
    """Get details for a specific ransomware group."""
    cache_key = f"group_{group_name}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/group/{group_name}")
    if isinstance(data, dict) and "error" in data:
        return data

    _set_cached(cache_key, data)
    return data


async def get_group_victims(group_name: str):
    """Get all victims claimed by a specific group."""
    cache_key = f"group_victims_{group_name}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/groupvictims/{group_name}")
    if isinstance(data, dict) and "error" in data:
        return data

    victims = [_normalize_victim(v, group_name) for v in data] if isinstance(data, list) else []
    _set_cached(cache_key, victims)
    return victims


async def get_country_victims(country_code: str = "IN"):
    """Get victims in a specific country."""
    cache_key = f"country_victims_{country_code}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/countryvictims/{country_code}")
    if isinstance(data, dict) and "error" in data:
        return data

    victims = [_normalize_victim(v) for v in data] if isinstance(data, list) else []
    # Ensure country field is set
    for v in victims:
        if not v["country"]:
            v["country"] = country_code
            v["country_name"] = COUNTRY_NAMES.get(country_code.upper(), country_code)

    _set_cached(cache_key, victims)
    return victims


async def search_victims(keyword: str):
    """Search victims by keyword."""
    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/searchvictims/{keyword}")
    if isinstance(data, dict) and "error" in data:
        return data
    return [_normalize_victim(v) for v in data] if isinstance(data, list) else []


async def get_recent_cyberattacks():
    """Get recent cyberattacks from ransomware.live."""
    cached = _get_cached("recent_cyberattacks")
    if cached:
        return cached
    data = await _fetch_json(f"{RANSOMWARE_LIVE_BASE}/recentcyberattacks")
    if isinstance(data, dict) and "error" in data:
        return data
    _set_cached("recent_cyberattacks", data)
    return data


# ─── CISA KEV (Known Exploited Vulnerabilities) ────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Map known CVEs to ransomware groups for cross-referencing
CVE_GROUP_MAP = {
    # LockBit
    "CVE-2023-4966": ["lockbit"],       # Citrix Bleed
    "CVE-2021-22986": ["lockbit"],       # F5 BIG-IP
    "CVE-2023-0669": ["clop"],           # GoAnywhere MFT
    "CVE-2023-34362": ["clop"],          # MOVEit Transfer
    "CVE-2023-35036": ["clop"],          # MOVEit Transfer
    "CVE-2021-27101": ["clop"],          # Accellion FTA
    "CVE-2021-27104": ["clop"],          # Accellion FTA
    "CVE-2023-20269": ["akira", "lockbit"],  # Cisco ASA/AnyConnect VPN
    "CVE-2020-3259": ["akira"],          # Cisco ASA
    "CVE-2021-21972": ["alphv"],         # VMware vCenter
    "CVE-2021-21974": ["alphv"],         # VMware ESXi
    "CVE-2021-31207": ["bianlian"],      # ProxyShell
    "CVE-2021-34473": ["bianlian", "lockbit"],  # ProxyShell
    "CVE-2021-34523": ["bianlian"],      # ProxyShell
    "CVE-2023-27350": ["lockbit", "clop"],  # PaperCut
    "CVE-2023-46604": ["royal"],         # Apache ActiveMQ
    "CVE-2022-47966": ["lockbit"],       # ManageEngine
    "CVE-2023-22515": ["alphv"],         # Confluence
    "CVE-2024-1709": ["lockbit", "alphv", "play"],  # ConnectWise ScreenConnect
    "CVE-2023-48788": ["medusa"],        # FortiClientEMS
}

def _normalize_kev(entry):
    """Normalize a CISA KEV entry."""
    cve_id = entry.get("cveID", "")
    is_ransomware = entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"
    linked_groups = CVE_GROUP_MAP.get(cve_id, [])

    return {
        "cve_id": cve_id,
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "name": entry.get("vulnerabilityName", ""),
        "description": entry.get("shortDescription", ""),
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "required_action": entry.get("requiredAction", ""),
        "ransomware_use": is_ransomware,
        "notes": entry.get("notes", ""),
        "linked_groups": linked_groups,
    }


async def get_cisa_kev(ransomware_only: bool = False):
    """Fetch the CISA KEV catalog."""
    cache_key = "cisa_kev"
    cached = _get_cached(cache_key)
    if cached:
        entries = cached
    else:
        data = await _fetch_json(CISA_KEV_URL, timeout=60.0)
        if isinstance(data, dict) and "error" in data:
            return data
        raw = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        entries = [_normalize_kev(e) for e in raw]
        # Sort by date_added descending (newest first)
        entries.sort(key=lambda e: e.get("date_added", ""), reverse=True)
        _set_cached(cache_key, entries)

    if ransomware_only:
        entries = [e for e in entries if e["ransomware_use"]]

    return entries


async def get_kev_stats():
    """Get KEV statistics for the dashboard."""
    cached = _get_cached("kev_stats")
    if cached:
        return cached

    entries = await get_cisa_kev()
    if isinstance(entries, dict) and "error" in entries:
        return entries

    total = len(entries)
    ransomware_count = sum(1 for e in entries if e["ransomware_use"])

    # Top vendors targeted
    vendor_counts = Counter()
    for e in entries:
        vendor_counts[e["vendor"]] += 1
    top_vendors = [{"vendor": v, "count": c} for v, c in vendor_counts.most_common(10)]

    # Recent additions (last 30 days)
    now = datetime.utcnow()
    recent = []
    for e in entries:
        try:
            dt = datetime.strptime(e["date_added"], "%Y-%m-%d")
            if (now - dt).days <= 30:
                recent.append(e)
        except (ValueError, TypeError):
            pass

    # Entries with linked ransomware groups
    group_linked = [e for e in entries if e["linked_groups"]]

    stats = {
        "total_kevs": total,
        "ransomware_linked": ransomware_count,
        "ransomware_percentage": round((ransomware_count / max(total, 1)) * 100, 1),
        "recent_30d": len(recent),
        "recent_entries": recent[:20],
        "top_vendors": top_vendors,
        "group_linked_count": len(group_linked),
    }

    _set_cached("kev_stats", stats)
    return stats


# ─── RansomLook API ─────────────────────────────────────────────────

async def get_ransomlook_recent():
    cached = _get_cached("ransomlook_recent")
    if cached:
        return cached
    data = await _fetch_json(f"{RANSOMLOOK_BASE}/recent")
    if isinstance(data, dict) and "error" in data:
        return data
    _set_cached("ransomlook_recent", data)
    return data

async def get_ransomlook_groups():
    cached = _get_cached("ransomlook_groups")
    if cached:
        return cached
    data = await _fetch_json(f"{RANSOMLOOK_BASE}/groups")
    if isinstance(data, dict) and "error" in data:
        return data
    _set_cached("ransomlook_groups", data)
    return data


# ─── Analytics & aggregation ────────────────────────────────────────

async def get_tracker_dashboard():
    """
    Build a comprehensive GLOBAL dashboard combining data from all sources.
    Returns: stats, top groups, recent victims, full country breakdown, timeline.
    """
    cached = _get_cached("tracker_dashboard")
    if cached:
        return cached

    # Fetch recent victims (global) — get ALL victims the API returns
    victims = await get_recent_victims(limit=0)
    if isinstance(victims, dict) and "error" in victims:
        victims = []

    # Fetch groups
    groups = await get_all_groups()
    if isinstance(groups, dict) and "error" in groups:
        groups = []

    # ── Compute stats ──

    # Top groups by victim count
    group_counts = Counter()
    for v in victims:
        group_counts[v.get("group_name", "Unknown")] += 1
    top_groups = [{"name": g, "count": c} for g, c in group_counts.most_common(20)]

    # FULL country breakdown (all countries worldwide)
    country_counts = Counter()
    for v in victims:
        cc = (v.get("country") or "").upper()
        if cc:
            country_counts[cc] += 1
    all_countries = [
        {
            "code": c,
            "name": COUNTRY_NAMES.get(c, c),
            "count": n,
        }
        for c, n in country_counts.most_common()
    ]

    # Sector breakdown
    sector_counts = Counter()
    for v in victims:
        sector = v.get("activity", "")
        if sector:
            sector_counts[sector] += 1
    top_sectors = [{"sector": s, "count": n} for s, n in sector_counts.most_common(15)]

    # Timeline (victims per day for last 30 days)
    timeline = defaultdict(int)
    now = datetime.utcnow()
    for v in victims:
        disc = v.get("discovered", "")
        if disc:
            try:
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        dt = datetime.strptime(disc[:19], fmt[:len(disc)])
                        break
                    except ValueError:
                        continue
                else:
                    continue
                day_key = dt.strftime("%Y-%m-%d")
                if (now - dt).days <= 30:
                    timeline[day_key] += 1
            except Exception:
                pass

    sorted_timeline = sorted(timeline.items())
    timeline_data = [{"date": d, "count": c} for d, c in sorted_timeline]

    # Per-country victim lists for quick drill-down (top 30 countries)
    country_victims_map = defaultdict(list)
    for v in victims:
        cc = (v.get("country") or "").upper()
        if cc:
            country_victims_map[cc].append(v)

    # Count unique countries attacked
    total_countries_hit = len(country_counts)

    dashboard = {
        "stats": {
            "total_recent_victims": len(victims),
            "total_groups": len(groups),
            "total_countries_hit": total_countries_hit,
            "top_group": top_groups[0]["name"] if top_groups else "N/A",
            "top_group_count": top_groups[0]["count"] if top_groups else 0,
            "top_country": all_countries[0]["name"] if all_countries else "N/A",
            "top_country_code": all_countries[0]["code"] if all_countries else "",
            "top_country_count": all_countries[0]["count"] if all_countries else 0,
        },
        "recent_victims": victims,
        "top_groups": top_groups,
        "all_countries": all_countries,
        "top_sectors": top_sectors,
        "timeline": timeline_data,
        "groups_directory": [
            {"name": g.get("name", ""), "description": g.get("description", "")}
            for g in groups
        ],
        "last_updated": datetime.utcnow().isoformat(),
    }

    _set_cached("tracker_dashboard", dashboard)
    return dashboard


# ─── FastAPI routes ─────────────────────────────────────────────────

def register_ransomware_routes(app):
    """Register all ransomware tracker API routes on the FastAPI app."""
    from fastapi import Query

    @app.get("/api/ransomware/dashboard")
    async def ransomware_dashboard():
        """Get the full global ransomware tracker dashboard data."""
        return await get_tracker_dashboard()

    @app.get("/api/ransomware/victims/recent")
    async def ransomware_recent_victims(limit: int = Query(0, ge=0)):
        """Get recent ransomware victims worldwide. limit=0 means all."""
        return await get_recent_victims(limit=limit)

    @app.get("/api/ransomware/groups")
    async def ransomware_groups():
        """Get all ransomware groups."""
        return await get_all_groups()

    @app.get("/api/ransomware/group/{group_name}")
    async def ransomware_group_detail(group_name: str):
        """Get details for a specific ransomware group."""
        return await get_group_detail(group_name)

    @app.get("/api/ransomware/group/{group_name}/victims")
    async def ransomware_group_victims(group_name: str):
        """Get victims claimed by a specific group."""
        return await get_group_victims(group_name)

    @app.get("/api/ransomware/victims/country/{country_code}")
    async def ransomware_country_victims(country_code: str):
        """Get ransomware victims by country (ISO-2 code). Works for ANY country."""
        return await get_country_victims(country_code.upper())

    @app.get("/api/ransomware/victims/search/{keyword}")
    async def ransomware_search_victims(keyword: str):
        """Search ransomware victims by keyword."""
        return await search_victims(keyword)

    @app.get("/api/ransomware/cyberattacks/recent")
    async def ransomware_recent_attacks():
        """Get recent cyberattacks."""
        return await get_recent_cyberattacks()

    @app.get("/api/ransomware/ransomlook/recent")
    async def ransomlook_recent():
        """Get recent posts from RansomLook."""
        return await get_ransomlook_recent()

    @app.get("/api/ransomware/ransomlook/groups")
    async def ransomlook_groups():
        """Get groups from RansomLook."""
        return await get_ransomlook_groups()

    @app.get("/api/ransomware/countries")
    async def ransomware_country_list():
        """Get full list of countries with victim counts."""
        dashboard = await get_tracker_dashboard()
        if isinstance(dashboard, dict) and "error" in dashboard:
            return dashboard
        return dashboard.get("all_countries", [])

    # ── CISA KEV endpoints ──

    @app.get("/api/ransomware/kev")
    async def cisa_kev_all(ransomware_only: bool = Query(False)):
        """Get CISA Known Exploited Vulnerabilities catalog."""
        return await get_cisa_kev(ransomware_only=ransomware_only)

    @app.get("/api/ransomware/kev/stats")
    async def cisa_kev_stats():
        """Get KEV statistics and recent additions."""
        return await get_kev_stats()

    @app.get("/api/ransomware/kev/search/{keyword}")
    async def cisa_kev_search(keyword: str):
        """Search KEV entries by CVE ID, vendor, product, or description."""
        entries = await get_cisa_kev()
        if isinstance(entries, dict) and "error" in entries:
            return entries
        q = keyword.lower()
        return [e for e in entries if
            q in e["cve_id"].lower() or
            q in e["vendor"].lower() or
            q in e["product"].lower() or
            q in e["name"].lower() or
            q in e["description"].lower()
        ]
