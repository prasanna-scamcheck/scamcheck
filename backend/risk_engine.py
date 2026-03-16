"""
Risk Scoring Engine and Search Utilities for ScamCheck.
"""
import re
from typing import Optional


# ── Indicator Type Detection ──

def detect_indicator_type(value: str) -> Optional[str]:
    """Auto-detect the type of an indicator from its value."""
    v = value.strip()

    # Phone number
    if re.match(r'^\+?\d[\d\s\-]{7,14}$', v):
        return "phone"

    # UPI ID (Indian UPI handles)
    upi_suffixes = r'@(ok|oksbi|ybl|paytm|apl|axl|ibl|upi|icici|hdfcbank|sbi|kotak|indus|federal|boi|cnrb|pnb|cbin|punb|dbs|hsbc|rbl|scb|utib|vijb|dlb)'
    if re.search(upi_suffixes, v, re.IGNORECASE):
        return "upi"

    # Bank account (alphanumeric, 11-20 chars)
    if re.match(r'^[A-Z]{4}\d{11,18}$', v, re.IGNORECASE):
        return "bank_account"

    # Crypto wallet
    if re.match(r'^0x[a-fA-F0-9]{6,}', v) or re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', v):
        return "wallet"

    # Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
        return "email"

    # Domain
    if re.match(r'^[a-zA-Z0-9.-]+\.(com|in|org|net|co|io|xyz|info|biz|app|dev)$', v, re.IGNORECASE):
        return "domain"

    return None


def normalize_indicator(value: str) -> str:
    """Normalize an indicator value for consistent searching."""
    v = value.strip().lower()
    # Remove spaces, dashes, plus signs from phone-like values
    v = re.sub(r'[\s\-\+\(\)]', '', v)
    return v


# ── Risk Score Calculation ──

def calculate_risk_score(
    complaint_count: int,
    linked_count: int = 0,
    has_verified_confirmation: bool = False,
    indicator_type: str = "phone",
    report_frequency_days: float = 30.0,
) -> float:
    """
    Calculate risk score (0-100) based on multiple signals.

    Factors:
    - complaint_count: Number of reports (heaviest weight)
    - linked_count: Number of linked fraud indicators
    - has_verified_confirmation: Investigator verification
    - indicator_type: UPI/bank are higher risk by nature
    - report_frequency_days: Average days between reports (lower = more active)
    """
    score = 0.0

    # Complaint count (0-45 points)
    if complaint_count >= 20:
        score += 45
    elif complaint_count >= 10:
        score += 35
    elif complaint_count >= 5:
        score += 25
    elif complaint_count >= 3:
        score += 18
    elif complaint_count >= 1:
        score += 10

    # Linked indicators (0-20 points)
    if linked_count >= 5:
        score += 20
    elif linked_count >= 3:
        score += 15
    elif linked_count >= 1:
        score += 8

    # Report frequency — more frequent = higher risk (0-15 points)
    if report_frequency_days <= 3:
        score += 15
    elif report_frequency_days <= 7:
        score += 12
    elif report_frequency_days <= 14:
        score += 8
    elif report_frequency_days <= 30:
        score += 4

    # Indicator type weighting (0-10 points)
    type_weights = {
        "upi": 8, "bank_account": 8, "wallet": 7,
        "domain": 6, "email": 5, "phone": 4
    }
    score += type_weights.get(indicator_type, 4)

    # Verified confirmation (0-10 points)
    if has_verified_confirmation:
        score += 10

    return min(100.0, round(score, 1))


def get_risk_level(score: float) -> str:
    """Return human-readable risk level."""
    if score <= 20:
        return "Safe"
    elif score <= 50:
        return "Suspicious"
    elif score <= 80:
        return "High Risk"
    return "Confirmed Fraud"


def get_recommendation(score: float, category: str = "") -> str:
    """Return actionable recommendation based on risk score."""
    if score > 80:
        return (
            "DO NOT transfer money or share personal information. "
            "This identifier is linked to confirmed fraud. "
            "Report immediately to cybercrime.gov.in or call 1930."
        )
    elif score > 50:
        return (
            "Exercise extreme caution. Multiple fraud reports exist for this identifier. "
            "Verify independently through official channels before proceeding with any transaction."
        )
    elif score > 20:
        return (
            "Some reports have been filed against this identifier. "
            "Proceed with caution and verify the source before sharing money or personal data."
        )
    return (
        "No significant fraud reports found. However, always verify independently "
        "and never share OTPs or passwords with anyone."
    )
