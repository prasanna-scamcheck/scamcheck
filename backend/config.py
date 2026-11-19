import os
import secrets

# ── Database ──
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scamcheck.db")

# ── Security ──
# IMPORTANT: Set these as environment variables on Render.
# Never rely on defaults in production.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(64)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(32)
    print(f"[WARNING] ADMIN_PASSWORD not set. Generated temporary password. Set it in environment variables.")
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# ── CORS ──
_default_origins = "http://localhost:3000,http://127.0.0.1:3000,https://cyberintelengine.com,https://www.cyberintelengine.com"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", _default_origins).split(",")

# ── Rate Limiting ──
RATE_LIMIT_SEARCH = "30/minute"
RATE_LIMIT_REPORT = "5/minute"

# ── File Uploads ──
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
