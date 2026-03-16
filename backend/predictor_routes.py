"""
ScamCheck — Scam Predictor API Routes
Add these to main.py (or import as a router)

To add to main.py, add these imports at the top:
    from scam_predictor import analyze_message, get_all_scam_dna, get_scam_dna_detail, get_live_scam_radar

Then add these route blocks.
"""

# ── ADD THESE ROUTES TO main.py ──

# ══════════════════════════════════════════════════════════════════
# SCAM PREDICTOR API
# ══════════════════════════════════════════════════════════════════

# Route 1: Analyze a suspicious message
@app.post("/api/predict")
def predict_scam(request: dict):
    """
    THE USP: Paste any suspicious message → get the complete scam playbook.
    Shows every step the scammer will take, money trail, and prevention tips.
    """
    message = request.get("message", "").strip()
    if not message or len(message) < 5:
        raise HTTPException(status_code=400, detail="Message too short. Paste the full suspicious message.")
    
    from scam_predictor import analyze_message
    result = analyze_message(message)
    return result


# Route 2: Get all scam DNA patterns (Scam Library)
@app.get("/api/scam-library")
def get_scam_library():
    """Return all mapped scam DNA patterns — the complete scam encyclopedia."""
    from scam_predictor import get_all_scam_dna
    return get_all_scam_dna()


# Route 3: Get detailed DNA for a specific scam type
@app.get("/api/scam-library/{scam_id}")
def get_scam_detail(scam_id: str):
    """Get the full playbook for a specific scam type."""
    from scam_predictor import get_scam_dna_detail
    result = get_scam_dna_detail(scam_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scam type not found")
    return result


# Route 4: Live Scam Radar
@app.get("/api/scam-radar")
def scam_radar(db: Session = Depends(get_db)):
    """Real-time scam activity by city — like a weather radar for fraud."""
    from scam_predictor import get_live_scam_radar
    return get_live_scam_radar(db)
