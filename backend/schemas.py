from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
import re


# ── Indicator Schemas ──

class IndicatorBase(BaseModel):
    type: str = Field(..., pattern="^(phone|upi|bank_account|email|domain|wallet)$")
    value: str = Field(..., min_length=3, max_length=500)
    category: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None


class IndicatorResponse(BaseModel):
    id: int
    ref_id: str
    type: str
    value: str
    risk_score: float
    complaint_count: int
    category: Optional[str]
    location: Optional[str]
    status: str
    notes: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    linked_indicators: Optional[List[dict]] = None

    class Config:
        from_attributes = True


class SearchResponse(BaseModel):
    found: bool
    query: str
    detected_type: Optional[str]
    result: Optional[IndicatorResponse] = None
    recommendation: Optional[str] = None


# ── Report Schemas ──

class ReportCreate(BaseModel):
    indicator_value: str = Field(..., min_length=3, max_length=500)
    indicator_type: str = Field(..., pattern="^(phone|upi|bank_account|email|domain|wallet)$")
    category: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=10, max_length=5000)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)

    @field_validator("indicator_value")
    @classmethod
    def sanitize_indicator(cls, v):
        # Basic XSS/injection prevention
        v = re.sub(r'[<>"\';]', '', v.strip())
        return v

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v):
        v = re.sub(r'<[^>]+>', '', v.strip())
        return v


class ReportResponse(BaseModel):
    id: int
    ref_id: str
    indicator_value: str
    indicator_type: str
    category: Optional[str]
    description: str
    city: Optional[str]
    state: Optional[str]
    status: str
    submitted_at: Optional[str]

    class Config:
        from_attributes = True


class ReportModerate(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")
    reviewer_notes: Optional[str] = None


# ── Stats Schemas ──

class DashboardStats(BaseModel):
    total_indicators: int
    total_reports: int
    confirmed_fraud: int
    pending_reports: int
    high_risk_count: int
    categories: List[dict]
    type_distribution: List[dict]
    recent_high_risk: List[dict]


# ── Auth Schemas ──

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
