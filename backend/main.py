"""
CyberIntelEngine — Cybercrime Intelligence Search Engine
Main FastAPI Application
"""
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc
from datetime import datetime
from typing import Optional
import os

import config
from models import get_db, create_tables, Indicator, Report, AdminUser, indicator_links
from schemas import (
    ReportCreate, ReportResponse, IndicatorResponse,
    SearchResponse, DashboardStats, LoginRequest, TokenResponse
)
from risk_engine import (
    detect_indicator_type, normalize_indicator,
    calculate_risk_score, get_risk_level, get_recommendation
)

# ── App Setup ──
app = FastAPI(
    title="CyberIntelEngine API",
    description="Cybercrime Intelligence Search Engine — verify before you trust or pay.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup
@app.on_event("startup")
def startup():
    create_tables()
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════
# SEARCH API
# ══════════════════════════════════════════════════════════════════

@app.get("/api/search", response_model=SearchResponse)
def search_indicator(
    q: str = Query(..., min_length=2, max_length=500, description="Search query"),
    db: Session = Depends(get_db)
):
    """
    Search the intelligence database for a phone, UPI, email, domain, etc.
    Returns risk score, complaint count, linked indicators, and recommendation.
    """
    query = q.strip()
    normalized = normalize_indicator(query)
    detected_type = detect_indicator_type(query)

    # Search by normalized value (fuzzy: contains match)
    result = db.query(Indicator).filter(
        or_(
            Indicator.normalized_value.contains(normalized),
            Indicator.normalized_value == normalized,
            Indicator.value.ilike(f"%{query}%"),
        )
    ).first()

    if not result:
        return SearchResponse(
            found=False,
            query=query,
            detected_type=detected_type,
            recommendation="No reports found. Always verify independently."
        )

    return SearchResponse(
        found=True,
        query=query,
        detected_type=detected_type or result.type,
        result=IndicatorResponse(**result.to_dict(include_linked=True)),
        recommendation=get_recommendation(result.risk_score, result.category or "")
    )


# ══════════════════════════════════════════════════════════════════
# INDICATORS API
# ══════════════════════════════════════════════════════════════════

@app.get("/api/indicators")
def list_indicators(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    type: Optional[str] = None,
    sort: str = Query("risk_score", pattern="^(risk_score|complaint_count|last_seen)$"),
    db: Session = Depends(get_db)
):
    """List all indicators with pagination, filtering, and sorting."""
    query = db.query(Indicator)

    if type:
        query = query.filter(Indicator.type == type)

    sort_col = getattr(Indicator, sort, Indicator.risk_score)
    query = query.order_by(desc(sort_col))

    total = query.count()
    indicators = query.offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "indicators": [ind.to_dict() for ind in indicators]
    }


@app.get("/api/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    """Get a single indicator with full linked intelligence."""
    ind = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ind.to_dict(include_linked=True)


# ══════════════════════════════════════════════════════════════════
# REPORTS API
# ══════════════════════════════════════════════════════════════════

@app.post("/api/reports", response_model=ReportResponse)
def submit_report(report: ReportCreate, db: Session = Depends(get_db)):
    """
    Submit a new fraud report. Enters moderation queue.
    """
    # Generate reference ID
    count = db.query(Report).count()
    ref_id = f"RPT-{count + 1:04d}"

    # Check if indicator already exists
    normalized = normalize_indicator(report.indicator_value)
    existing = db.query(Indicator).filter(
        Indicator.normalized_value == normalized
    ).first()

    new_report = Report(
        ref_id=ref_id,
        indicator_value=report.indicator_value,
        indicator_type=report.indicator_type,
        category=report.category,
        description=report.description,
        city=report.city,
        state=report.state,
        status="pending",
        indicator_id=existing.id if existing else None,
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return ReportResponse(**new_report.to_dict())


@app.get("/api/reports/pending")
def get_pending_reports(db: Session = Depends(get_db)):
    """Get all pending reports for moderation."""
    reports = db.query(Report).filter(
        Report.status == "pending"
    ).order_by(desc(Report.submitted_at)).all()
    return [r.to_dict() for r in reports]


@app.post("/api/reports/{report_id}/approve")
def approve_report(report_id: int, db: Session = Depends(get_db)):
    """
    Approve a report: updates or creates the indicator, recalculates risk score.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "pending":
        raise HTTPException(status_code=400, detail="Report already processed")

    normalized = normalize_indicator(report.indicator_value)
    existing = db.query(Indicator).filter(
        Indicator.normalized_value == normalized
    ).first()

    if existing:
        # Update existing indicator
        existing.complaint_count += 1
        existing.last_seen = datetime.utcnow()
        existing.risk_score = calculate_risk_score(
            complaint_count=existing.complaint_count,
            linked_count=len(existing.linked_indicators),
            indicator_type=existing.type,
        )
        if existing.risk_score > 80:
            existing.status = "confirmed"
        elif existing.risk_score > 50:
            existing.status = "active"
        report.indicator_id = existing.id
    else:
        # Create new indicator
        ind_count = db.query(Indicator).count()
        new_ind = Indicator(
            ref_id=f"IND-{ind_count + 1:04d}",
            type=report.indicator_type,
            value=report.indicator_value,
            normalized_value=normalized,
            risk_score=calculate_risk_score(
                complaint_count=1,
                indicator_type=report.indicator_type,
            ),
            complaint_count=1,
            category=report.category,
            location=f"{report.city or ''}, {report.state or ''}".strip(", "),
            status="unverified",
            notes=report.description,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(new_ind)
        db.flush()
        report.indicator_id = new_ind.id

    report.status = "approved"
    report.reviewed_at = datetime.utcnow()
    db.commit()

    return {"message": "Report approved", "report_id": report.id}


@app.post("/api/reports/{report_id}/reject")
def reject_report(report_id: int, db: Session = Depends(get_db)):
    """Reject a report — removes it from the queue."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "pending":
        raise HTTPException(status_code=400, detail="Report already processed")

    report.status = "rejected"
    report.reviewed_at = datetime.utcnow()
    db.commit()

    return {"message": "Report rejected", "report_id": report.id}


# ══════════════════════════════════════════════════════════════════
# STATISTICS & TRENDS API
# ══════════════════════════════════════════════════════════════════

@app.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Dashboard statistics for the admin panel."""
    total_indicators = db.query(Indicator).count()
    total_reports = db.query(func.sum(Indicator.complaint_count)).scalar() or 0
    confirmed_fraud = db.query(Indicator).filter(Indicator.risk_score > 80).count()
    pending_reports = db.query(Report).filter(Report.status == "pending").count()
    high_risk = db.query(Indicator).filter(Indicator.risk_score > 50).count()

    # Category breakdown
    categories = db.query(
        Indicator.category, func.sum(Indicator.complaint_count).label("count")
    ).group_by(Indicator.category).order_by(desc("count")).all()

    # Type distribution
    types = db.query(
        Indicator.type, func.count(Indicator.id).label("count")
    ).group_by(Indicator.type).order_by(desc("count")).all()

    # Recent high-risk
    recent_hr = db.query(Indicator).filter(
        Indicator.risk_score > 60
    ).order_by(desc(Indicator.last_seen)).limit(10).all()

    return {
        "total_indicators": total_indicators,
        "total_reports": int(total_reports),
        "confirmed_fraud": confirmed_fraud,
        "pending_reports": pending_reports,
        "high_risk_count": high_risk,
        "categories": [{"category": c[0], "count": int(c[1])} for c in categories if c[0]],
        "type_distribution": [{"type": t[0], "count": t[1]} for t in types],
        "recent_high_risk": [ind.to_dict() for ind in recent_hr],
    }


@app.get("/api/trends")
def get_fraud_trends(db: Session = Depends(get_db)):
    """Fraud trend analytics — most reported, recent campaigns."""
    most_reported = db.query(Indicator).order_by(
        desc(Indicator.complaint_count)
    ).limit(10).all()

    recent_active = db.query(Indicator).order_by(
        desc(Indicator.last_seen)
    ).limit(10).all()

    return {
        "most_reported": [ind.to_dict() for ind in most_reported],
        "recent_active": [ind.to_dict() for ind in recent_active],
    }


# ══════════════════════════════════════════════════════════════════
# AUTH (Simple token-based for admin)
# ══════════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
def admin_login(req: LoginRequest):
    """Simple admin authentication."""
    if req.username == config.ADMIN_USERNAME and req.password == config.ADMIN_PASSWORD:
        from jose import jwt
        token = jwt.encode(
            {"sub": req.username, "exp": datetime.utcnow().timestamp() + 3600 * 8},
            config.SECRET_KEY, algorithm="HS256"
        )
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ══════════════════════════════════════════════════════════════════
# SCAM PREDICTOR API — THE USP
# "See the scam before it sees you"
# ══════════════════════════════════════════════════════════════════

@app.post("/api/predict")
def predict_scam(request: dict):
    """Paste any suspicious message → get the complete scam playbook."""
    message = request.get("message", "").strip()
    if not message or len(message) < 5:
        raise HTTPException(status_code=400, detail="Message too short")
    from scam_predictor import analyze_message
    return analyze_message(message)


@app.get("/api/scam-library")
def get_scam_library():
    """Return all mapped scam DNA patterns."""
    from scam_predictor import get_all_scam_dna
    return get_all_scam_dna()


@app.get("/api/scam-library/{scam_id}")
def get_scam_detail(scam_id: str):
    """Get the full playbook for a specific scam type."""
    from scam_predictor import get_scam_dna_detail
    result = get_scam_dna_detail(scam_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scam type not found")
    return result


@app.get("/api/scam-radar")
def scam_radar(db: Session = Depends(get_db)):
    """Real-time scam activity by city."""
    from scam_predictor import get_live_scam_radar
    return get_live_scam_radar(db)


# ══════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberIntelEngine API", "version": "1.0.0"}
