import os

# ── Database ──
# SQLite for development, switch to PostgreSQL for production
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scamcheck.db")

# ── Security ──
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "scamcheck2026")
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# ── CORS ──
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

# ── Rate Limiting ──
RATE_LIMIT_SEARCH = "30/minute"
RATE_LIMIT_REPORT = "5/minute"

# ── File Uploads ──
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
