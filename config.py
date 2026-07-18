import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = "/var/data" if os.path.isdir("/var/data") else str(BASE_DIR)
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(DATA_DIR, "winwin.db"))
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 72

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")  # Compared via hmac.compare_digest — never log this

GOD_MODE_SALT = os.getenv("GOD_MODE_SALT", "")
HMAC_SECRET_KEY = os.getenv("HMAC_SECRET_KEY", "")
FUNCTION_INTEGRITY_HASH = "function_guard_v2_sealed"
TIMEWALL_SECRET_KEY = os.getenv("TIMEWALL_SECRET_KEY", "")

# ── Fail-fast guard: crash immediately if critical secrets are missing ────
_REQUIRED_SECRETS = {
    "JWT_SECRET": JWT_SECRET,
    "ADMIN_PASSWORD": ADMIN_PASSWORD,
    "GOD_MODE_SALT": GOD_MODE_SALT,
    "HMAC_SECRET_KEY": HMAC_SECRET_KEY,
}
_missing = [k for k, v in _REQUIRED_SECRETS.items() if not v]
if _missing and not os.getenv("WINWIN_DEV_MODE"):
    raise RuntimeError(
        f"Missing required environment variables: {', '.join(_missing)}. "
        f"Set them in .env or export them. To skip this check during local dev, set WINWIN_DEV_MODE=1."
    )

FAST2SMS_API_KEY = os.getenv("FAST2SMS_API_KEY", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500,https://win-admin-panel.web.app,https://winwinpro.xyz").split(",") if o.strip()]

WINCASH_PER_RUPEE = 100
INITIAL_BONUS_WC = 5000
NORMAL_SIGNUP_BONUS_WC = 0
REFERRAL_CAP_WC = 10000
MIN_REDEEM_WC = 1000
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "arsong@modreator.com")
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
