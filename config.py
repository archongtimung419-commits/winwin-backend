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
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 72

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")  # Compared via hmac.compare_digest — never log this

GOD_MODE_SALT = os.getenv("GOD_MODE_SALT", "GodModeSecureWinWin_2026_Salt!#")
HMAC_SECRET_KEY = os.getenv("HMAC_SECRET_KEY", "WinWin_HMAC_K3y_$ecure_2026!@#_N3v3rExpose")
FUNCTION_INTEGRITY_HASH = "function_guard_v2_sealed"

FAST2SMS_API_KEY = os.getenv("FAST2SMS_API_KEY", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500,https://win-admin-panel.web.app,https://winwinpro.xyz").split(",") if o.strip()]

WINCASH_PER_RUPEE = 100
INITIAL_BONUS_WC = 5000
NORMAL_SIGNUP_BONUS_WC = 0
REFERRAL_CAP_WC = 10000
MIN_REDEEM_WC = 1000
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "arsong@modreator.com")
