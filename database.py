import os
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from config import DATABASE_PATH, GOD_MODE_SALT, HMAC_SECRET_KEY, INITIAL_BONUS_WC, NORMAL_SIGNUP_BONUS_WC, OWNER_EMAIL
from security import god_mode_sign, god_mode_verify

DATABASE_URL = os.getenv("DATABASE_URL", "")
IS_POSTGRES = DATABASE_URL.startswith("postgres")

if IS_POSTGRES:
    import psycopg2
    import psycopg2.extras

class DBConnectionWrapper:
    def __init__(self):
        self.is_pg = IS_POSTGRES
        if self.is_pg:
            self.conn = psycopg2.connect(DATABASE_URL)
        else:
            self.conn = sqlite3.connect(DATABASE_PATH)
            self.conn.row_factory = sqlite3.Row

    def execute(self, query, params=()):
        if self.is_pg:
            cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            query = query.replace("?", "%s")
            cur.execute(query, params)
            return cur
        else:
            return self.conn.execute(query, params)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

@contextmanager
def get_conn():
    conn = DBConnectionWrapper()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_user_fields(user_id: str, email: str, balance: float, is_vip: bool = False) -> dict[str, Any]:
    base = {
        "userId": user_id,
        "email": email,
        "username": email.split("@")[0] if "@" in email else email,
        "balance": balance,
        "isVip": is_vip,
        "accountStatus": "ACTIVE",
        "dailyStreak": 1,
        "onboarding_stage": 0,
        "createdAt": _now_iso(),
        "emailVerified": False,
        "referralsCount": 0,
        "referralCommissionEarned": 0,
        "videoAdsCompleted": 0,
        "completed_articles_count": 0,
        "directLinksCompleted": 0,
        "socialTasksCompleted": 0,
        "completed_app_installs": 0,
        "completedArticleIds": [],
        "completedSocialIds": [],
        "lastVideoAdTime": 0,
        "lastCpaInstallTime": 0,
        "withdrawals": [],
        "referralCodeUsed": "",
        "referralStatus": "",
        "withdrawalTier": "NEW_USER",
        "phoneVerified": False,
        "ledger": {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0},
        "pendingUploads": [],
        "completed_today_links": [],
        "video_states": {},
        "cooldowns": {},
        "lotteryTickets": 0,
        "notifications": [],
        "earningsHistory": [],
    }
    base.update(god_mode_sign(user_id, balance, is_vip, "ACTIVE", 1, GOD_MODE_SALT, HMAC_SECRET_KEY))
    return base





def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS withdrawals (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                amount REAL NOT NULL,
                method TEXT NOT NULL,
                account_details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        existing = conn.execute("SELECT 1 FROM system_settings WHERE key = 'platform_mode'").fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                ("platform_mode", "live", _now_iso()),
            )


def row_to_user(row: Any) -> dict[str, Any]:
    data = json.loads(row["data_json"])
    data["email"] = row["email"]
    return data


def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return row_to_user(row) if row else None


def get_user_by_email(email: str) -> tuple[dict[str, Any], str] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
        if not row:
            return None
        return row_to_user(row), row["password_hash"]


def save_user(user: dict[str, Any], password_hash: str | None = None) -> dict[str, Any]:
    user.update(
        god_mode_sign(
            user["userId"], user["balance"], user.get("isVip", False),
            user.get("accountStatus", "ACTIVE"), user.get("dailyStreak", 1),
            GOD_MODE_SALT, HMAC_SECRET_KEY
        )
    )

    payload = {k: v for k, v in user.items()}
    email = payload.pop("email")

    with get_conn() as conn:
        if password_hash:
            conn.execute(
                """
                INSERT INTO users (user_id, email, password_hash, data_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    email=excluded.email,
                    password_hash=excluded.password_hash,
                    data_json=excluded.data_json
                """,
                (user["userId"], email.lower(), password_hash, json.dumps(payload), user.get("createdAt", _now_iso())),
            )
        else:
            conn.execute(
                "UPDATE users SET data_json = ?, email = ? WHERE user_id = ?",
                (json.dumps(payload), email.lower(), user["userId"]),
            )
    user["email"] = email
    return user


def delete_user(user_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))


def create_user(email: str, password_hash: str, referral_code: str = "", user_id: str = "") -> dict[str, Any]:
    if user_id and get_user_by_id(user_id):
        uid = f"usr_{uuid.uuid4().hex[:12]}"
    else:
        uid = user_id or f"usr_{uuid.uuid4().hex[:12]}"
    is_owner = email.lower() == OWNER_EMAIL.lower()
    balance = INITIAL_BONUS_WC if is_owner else NORMAL_SIGNUP_BONUS_WC
    user = default_user_fields(uid, email, balance, is_vip=is_owner)
    if referral_code:
        user["referralCodeUsed"] = referral_code
        user["referralStatus"] = "PENDING"
    return save_user(user, password_hash)


def list_all_users() -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return [row_to_user(r) for r in rows]


def create_withdrawal(user_id: str, amount: float, method: str, account_details: str) -> dict[str, Any]:
    wid = f"WD-{uuid.uuid4().hex[:8].upper()}"
    created = _now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO withdrawals (id, user_id, amount, method, account_details, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
            """,
            (wid, user_id, amount, method, account_details, created),
        )
    return {"id": wid, "amount": amount, "method": method, "status": "PENDING", "createdAt": created}


def get_platform_metrics() -> dict[str, Any]:
    users = list_all_users()
    total_balance = sum(u.get("balance", 0) for u in users)
    return {
        "totalUsers": len(users),
        "totalEarnings": total_balance,
        "activeSessions": max(1, len([u for u in users if u.get("accountStatus") == "ACTIVE"])),
    }


def get_system_setting(key: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None


def set_system_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO system_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, value, _now_iso()),
        )


# ── Withdrawals ───────────────────────────────────────────────────────────────

def list_all_withdrawals() -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM withdrawals ORDER BY created_at DESC").fetchall()
        return [
            {
                "id": r["id"],
                "userId": r["user_id"],
                "amount": r["amount"],
                "method": r["method"],
                "accountDetails": r["account_details"],
                "status": r["status"],
                "createdAt": r["created_at"],
            }
            for r in rows
        ]


def update_withdrawal_status(wid: str, new_status: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM withdrawals WHERE id = ?", (wid,)).fetchone()
        if not row:
            return None
        if row["status"] in ["PAID", "REJECTED"]:
            return {"_resolved": True}
        conn.execute("UPDATE withdrawals SET status = ? WHERE id = ?", (new_status, wid))
        return {
            "id": wid,
            "userId": row["user_id"],
            "amount": row["amount"],
            "method": row["method"],
            "accountDetails": row["account_details"],
            "status": new_status,
            "createdAt": row["created_at"],
        }


# ── Content Config ───────────────────────────────────────────────────────────

def get_content_config() -> dict[str, Any] | None:
    raw = get_system_setting("content_config")
    if raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def set_content_config(config: dict[str, Any]) -> None:
    set_system_setting("content_config", json.dumps(config))
