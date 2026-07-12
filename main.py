from datetime import datetime, timedelta, timezone
from typing import Any

import hmac as _hmac

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    CORS_ORIGINS,
    FAST2SMS_API_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRE_HOURS,
    JWT_SECRET,
    MIN_REDEEM_WC,
    REFERRAL_CAP_WC,
)
from database import (
    create_user,
    create_withdrawal,
    get_content_config,
    get_platform_metrics,
    get_system_setting,
    get_user_by_email,
    get_user_by_id,
    init_db,
    list_all_users,
    list_all_withdrawals,
    save_user,
    set_content_config,
    set_system_setting,
    update_withdrawal_status,
)
from security import god_mode_verify

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

app = FastAPI(title="Win Win Pro API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ──────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    referral_code: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class TaskCompleteRequest(BaseModel):
    task_type: str
    amount: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReferralCreditRequest(BaseModel):
    referral_code: str
    amount: float


class WithdrawalRequest(BaseModel):
    amount: float
    method: str
    account_details: str


class OtpRequest(BaseModel):
    phone: str
    otp: str


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminUserPatch(BaseModel):
    balance: float | None = None
    isVip: bool | None = None
    accountStatus: str | None = None
    dailyStreak: int | None = None


class UserSyncRequest(BaseModel):
    uid: str
    email: str
    username: str = ""


# ── Auth helpers ─────────────────────────────────────────────────────────────

def create_token(subject: str, role: str = "user") -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": subject, "role": role, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def get_current_user(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not creds:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(creds.credentials)
    if payload.get("role") != "user":
        raise HTTPException(status_code=403, detail="User access only")
    user = get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    valid, layer = god_mode_verify(user, __import__("config").GOD_MODE_SALT, __import__("config").HMAC_SECRET_KEY)
    if not valid:
        user["accountStatus"] = "TAMPERED"
        save_user(user)
        raise HTTPException(status_code=403, detail=f"Account integrity violation (layer {layer})")
    return user


def get_admin(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not creds:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return payload


def verify_user_integrity(user: dict[str, Any]) -> None:
    valid, layer = god_mode_verify(user, __import__("config").GOD_MODE_SALT, __import__("config").HMAC_SECRET_KEY)
    if not valid:
        raise HTTPException(status_code=403, detail=f"Integrity check failed at layer {layer}")


# ── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ── System status (public — no auth required) ────────────────────────────────

@app.get("/api/system/status")
def get_system_status() -> dict[str, str]:
    mode = get_system_setting("platform_mode") or "live"
    return {"mode": mode}


class SystemStatusUpdate(BaseModel):
    mode: str


@app.put("/api/system/status")
def update_system_status(body: SystemStatusUpdate, _: dict[str, Any] = Depends(get_admin)) -> dict[str, str]:
    if body.mode not in ("live", "maintenance"):
        raise HTTPException(status_code=400, detail="Mode must be 'live' or 'maintenance'.")
    set_system_setting("platform_mode", body.mode)
    return {"mode": body.mode, "status": "updated"}


# ── Auth routes ──────────────────────────────────────────────────────────────

@app.post("/api/auth/register")
def register(body: RegisterRequest) -> dict[str, Any]:
    if get_user_by_email(body.email.lower()):
        raise HTTPException(status_code=400, detail="Username already registered.")
    user = create_user(body.email.lower(), pwd_context.hash(body.password), body.referral_code)
    token = create_token(user["userId"], "user")
    return {"token": token, "user": user}


@app.post("/api/auth/login")
def login(body: LoginRequest) -> dict[str, Any]:
    found = get_user_by_email(body.email.lower())
    if not found:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    user, password_hash = found
    if not pwd_context.verify(body.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    if user.get("accountStatus") == "TAMPERED":
        raise HTTPException(status_code=403, detail="Account locked due to tampering.")
    token = create_token(user["userId"], "user")
    return {"token": token, "user": user}


# ── User routes ──────────────────────────────────────────────────────────────

@app.get("/api/users/me")
def get_me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return user


@app.put("/api/users/me")
def update_me(updates: dict[str, Any], user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    protected = {"userId", "email", "dataSignature", "hmacSignature", "freezeGuard", "balance"}
    for key, value in updates.items():
        if key not in protected:
            user[key] = value
    return save_user(user)


@app.post("/api/users/sync")
def sync_user(body: UserSyncRequest) -> dict[str, Any]:
    """Sync a frontend-authenticated user into the backend SQLite database.
    Called by the frontend after Google/Phone sign-up so the admin panel sees them."""
    existing = get_user_by_id(body.uid)
    if existing:
        # User already exists — update email/username if changed
        if body.email and existing.get("email", "").lower() != body.email.lower():
            existing["email"] = body.email
        if body.username:
            existing["username"] = body.username
        return save_user(existing)

    # Check by email to avoid duplicates
    by_email = get_user_by_email(body.email.lower())
    if by_email:
        user, _ = by_email
        return user

    # Create new user in backend with a placeholder password hash (OAuth user — no local password)
    placeholder_hash = pwd_context.hash("__oauth_no_password__")
    user = create_user(body.email.lower(), placeholder_hash, user_id=body.uid)
    user["username"] = body.username or body.email.split("@")[0]
    return save_user(user, placeholder_hash)


@app.post("/api/tasks/complete")
def complete_task(body: TaskCompleteRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user.get("accountStatus") == "TAMPERED":
        raise HTTPException(status_code=403, detail="Account locked.")
    if body.amount <= 0 or body.amount > 5000:
        raise HTTPException(status_code=400, detail="Invalid reward amount.")

    user["balance"] = float(user.get("balance", 0)) + body.amount
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    ledger["grossWc"] = ledger.get("grossWc", 0) + body.amount
    ledger["userWc"] = ledger.get("userWc", 0) + body.amount

    history = user.setdefault("earningHistory", [])
    history.append({"task": body.task_type, "amount": body.amount, "at": datetime.now(timezone.utc).isoformat()})

    return save_user(user)


@app.post("/api/referrals/credit")
def credit_referral(body: ReferralCreditRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, str]:
    all_users = list_all_users()
    referrer = next(
        (u for u in all_users if u["userId"].endswith(body.referral_code) or u["userId"] == body.referral_code),
        None,
    )
    if not referrer:
        return {"status": "no_referrer"}

    rate = 0.15 if referrer.get("isVip") else 0.05
    commission = round(body.amount * rate)
    prev = referrer.get("referralCommissionEarned", 0)
    new_total = prev + commission
    added = commission
    if prev >= REFERRAL_CAP_WC:
        added = 0
    elif new_total > REFERRAL_CAP_WC:
        added = REFERRAL_CAP_WC - prev

    referrer["referralCommissionEarned"] = min(REFERRAL_CAP_WC, new_total)
    if added > 0:
        referrer["balance"] = float(referrer.get("balance", 0)) + added
    save_user(referrer)
    return {"status": "credited", "added": str(added)}


@app.post("/api/withdrawals")
def submit_withdrawal(body: WithdrawalRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if body.amount < MIN_REDEEM_WC:
        raise HTTPException(status_code=400, detail=f"Minimum redemption is {MIN_REDEEM_WC} WinCash.")
    if float(user.get("balance", 0)) < body.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance.")

    user["balance"] = float(user["balance"]) - body.amount
    withdrawal = create_withdrawal(user["userId"], body.amount, body.method, body.account_details)
    user.setdefault("withdrawals", []).append(withdrawal)
    save_user(user)
    return {"withdrawal": withdrawal, "user": user}


# ── OTP ──────────────────────────────────────────────────────────────────────

@app.post("/api/otp/send")
async def send_otp(body: OtpRequest) -> dict[str, Any]:
    if not FAST2SMS_API_KEY:
        return {"success": True, "message": "Mock OTP mode — use 123456 in dev"}

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://www.fast2sms.com/dev/bulkV2",
            headers={"authorization": FAST2SMS_API_KEY, "Content-Type": "application/json"},
            json={
                "route": "q",
                "message": f"Your WinWin Pro verification OTP is: {body.otp}. Do not share this with anyone.",
                "language": "english",
                "flash": 0,
                "numbers": body.phone,
            },
            timeout=15,
        )
    data = response.json()
    if data.get("return"):
        return {"success": True, "message": "OTP sent"}
    raise HTTPException(status_code=400, detail=data.get("message", "Failed to send OTP"))


# ── Admin routes ─────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
def admin_login(body: AdminLoginRequest) -> dict[str, str]:
    # Constant-time comparison to prevent timing attacks
    username_ok = _hmac.compare_digest(body.username, ADMIN_USERNAME)
    password_ok = _hmac.compare_digest(body.password, ADMIN_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return {"token": create_token("admin", "admin")}


@app.post("/api/admin/verify")
def verify_admin_access(body: AdminLoginRequest) -> dict[str, str]:
    """Server-side admin password verification — called by admin frontend."""
    if not body.password:
        raise HTTPException(status_code=400, detail="Missing credentials.")

    username_ok = _hmac.compare_digest(body.username, ADMIN_USERNAME)
    password_ok = _hmac.compare_digest(body.password, ADMIN_PASSWORD)

    if username_ok and password_ok:
        token = create_token("admin", "admin")
        return {"status": "success", "token": token}
    else:
        raise HTTPException(status_code=401, detail="Unauthorized access denied.")


@app.get("/api/admin/users")
def admin_users(_: dict[str, Any] = Depends(get_admin)) -> list[dict[str, Any]]:
    users = list_all_users()
    for u in users:
        u.pop("password", None)
    return users


@app.get("/api/admin/metrics")
def admin_metrics(_: dict[str, Any] = Depends(get_admin)) -> dict[str, Any]:
    return get_platform_metrics()


@app.patch("/api/admin/users/{user_id}")
def admin_patch_user(user_id: str, body: AdminUserPatch, _: dict[str, Any] = Depends(get_admin)) -> dict[str, Any]:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.balance is not None:
        user["balance"] = body.balance
    if body.isVip is not None:
        user["isVip"] = body.isVip
    if body.accountStatus is not None:
        user["accountStatus"] = body.accountStatus
    if body.dailyStreak is not None:
        user["dailyStreak"] = body.dailyStreak
    return save_user(user)


# ── Admin: Withdrawals ────────────────────────────────────────────────────────

@app.get("/api/admin/withdrawals")
def admin_withdrawals(_: dict[str, Any] = Depends(get_admin)) -> list[dict[str, Any]]:
    return list_all_withdrawals()


class WithdrawalStatusPatch(BaseModel):
    status: str = Field(..., pattern=r"^(APPROVED|REJECTED|PAID)$")


@app.patch("/api/admin/withdrawals/{wid}")
def admin_patch_withdrawal(wid: str, body: WithdrawalStatusPatch, _: dict[str, Any] = Depends(get_admin)) -> dict[str, Any]:
    result = update_withdrawal_status(wid, body.status)
    if not result:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    return result


# ── Admin: Content Config ─────────────────────────────────────────────────────

@app.get("/api/admin/content-config")
def admin_get_content_config(_: dict[str, Any] = Depends(get_admin)) -> dict[str, Any]:
    return get_content_config() or {}


@app.put("/api/admin/content-config")
def admin_put_content_config(body: dict[str, Any], _: dict[str, Any] = Depends(get_admin)) -> dict[str, Any]:
    set_content_config(body)
    return {"status": "ok"}
