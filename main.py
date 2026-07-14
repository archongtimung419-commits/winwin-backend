from datetime import datetime, timedelta, timezone
from typing import Any

import hmac as _hmac

import httpx
from fastapi import Depends, FastAPI, HTTPException, status, Request
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


class UpdateProfileRequest(BaseModel):
    uid: str
    new_username: str


class OnboardingRequest(BaseModel):
    uid: str
    name: str | None = None
    age: str | None = None
    gender: str | None = None
    state: str | None = None
    isFinalStep: bool = False


class UserMeUpdateRequest(BaseModel):
    username: str | None = None


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
    if user.get("accountStatus") == "BANNED":
        raise HTTPException(status_code=403, detail="Account is banned.")
    if user.get("accountStatus") == "TAMPERED":
        raise HTTPException(status_code=403, detail="Account locked due to tampering.")
    return user


def verify_user_active(user: dict[str, Any]) -> None:
    if user.get("accountStatus") != "ACTIVE":
        raise HTTPException(status_code=403, detail="Account is not active.")


def get_admin(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not creds:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return payload


# ── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ── System status ────────────────────────────────────────────────────────────

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
    if user.get("accountStatus") == "BANNED":
        raise HTTPException(status_code=403, detail="Account is banned.")
    token = create_token(user["userId"], "user")
    return {"token": token, "user": user}


# ── User routes ──────────────────────────────────────────────────────────────

@app.get("/api/users/me")
def get_me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    thirty_days_ago = now - timedelta(days=30)
    history = user.get("earningsHistory") or user.get("earningHistory") or []
    def _ts(e):
        t = e.get("timestamp") or e.get("date")
        if t is None:
            return None
        if isinstance(t, (int, float)):
            return datetime.fromtimestamp(t / 1000 if t > 1e12 else t, tz=timezone.utc)
        return datetime.fromisoformat(t.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    user["todays_earnings"] = sum(e.get("amount", 0) for e in history if _ts(e) and _ts(e) >= today_start)
    user["last_30_days"] = sum(e.get("amount", 0) for e in history if _ts(e) and _ts(e) >= thirty_days_ago)
    user["earnings"] = user.get("balance", 0)
    user["offers_completed"] = (
        user.get("videoAdsCompleted", 0) + user.get("completed_articles_count", 0)
        + user.get("directLinksCompleted", 0) + user.get("socialTasksCompleted", 0)
        + user.get("completed_app_installs", 0)
    )
    return user


@app.put("/api/users/me")
def update_me(body: UserMeUpdateRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    if body.username is not None:
        user["username"] = body.username
    return save_user(user)


import uuid

@app.post("/api/users/onboarding")
def complete_onboarding(body: OnboardingRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    if user.get("onboardingCompleted"):
        return {"message": "Already onboarded", "user": user}

    reward = 0
    if body.name and not user.get("name"):
        user["username"] = body.name
        user["name"] = body.name
        reward += 25
    if body.age and not user.get("age"):
        user["age"] = body.age
        reward += 25
    if body.gender and not user.get("gender"):
        user["gender"] = body.gender
        reward += 25
    if body.state and not user.get("state"):
        user["state"] = body.state
        reward += 25

    if reward > 0:
        user["balance"] = user.get("balance", 0.0) + float(reward)
        user["earnings"] = user.get("earnings", 0.0) + float(reward)
        history = user.get("earningsHistory", [])
        tx_id = f"TX_ONBOARD_{int(datetime.now(timezone.utc).timestamp())}_{uuid.uuid4().hex[:4]}"
        history.append({
            "id": tx_id,
            "type": "onboarding_reward",
            "name": "Profile Completion",
            "amount": reward,
            "date": datetime.now(timezone.utc).isoformat(),
            "status": "Paid"
        })
        user["earningsHistory"] = history

    if body.isFinalStep:
        user["onboardingCompleted"] = True
        if not user.get("ob_m1_done"):
            user["ob_m1_done"] = True
            user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1
        
    return save_user(user)


@app.post("/api/users/sync")
def sync_user(body: UserSyncRequest) -> dict[str, Any]:
    existing = get_user_by_id(body.uid)
    if existing:
        if body.email and existing.get("email", "").lower() != body.email.lower():
            existing["email"] = body.email
        if body.username:
            existing["username"] = body.username
        return save_user(existing)

    by_email = get_user_by_email(body.email.lower())
    if by_email:
        user, _ = by_email
        return user

    placeholder_hash = pwd_context.hash("__oauth_no_password__")
    user = create_user(body.email.lower(), placeholder_hash, user_id=body.uid)
    user["username"] = body.username or body.email.split("@")[0]

    return save_user(user, placeholder_hash)


@app.post("/api/update-profile")
def update_profile(body: UpdateProfileRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    user["username"] = body.new_username
    return save_user(user)


# ── Task reward config ───────────────────────────────────────────────────────

TASK_REWARDS = {
    "videoAd": 3,
    "articleRead": 3,
    "directLink": 3,
    "socialFollow": 28,
    "googleGig": 200,
    "webMicroGig": 200,
    "casualGame": 5,
    "socialMicro": 15,
    "customTask": 300,
    "cpaCPL": 500,
}


@app.post("/api/tasks/complete")
def complete_task(body: TaskCompleteRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)

    reward = TASK_REWARDS.get(body.task_type)
    if reward is None:
        raise HTTPException(status_code=400, detail=f"Unknown task type: {body.task_type}")
    if reward <= 0:
        raise HTTPException(status_code=400, detail="Invalid reward amount.")

    user["balance"] = float(user.get("balance", 0)) + reward
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    ledger["grossWc"] = ledger.get("grossWc", 0) + reward
    ledger["userWc"] = ledger.get("userWc", 0) + reward

    history = user.get("earningsHistory") or user.get("earningHistory") or []
    if isinstance(history, dict):
        history = []
    history.append({"task": body.task_type, "amount": reward, "at": datetime.now(timezone.utc).isoformat()})
    
    # Onboarding Milestones Check
    m2_tasks = ["socialFollow", "socialMicro", "social"]
    m3_tasks = ["articleRead", "shortlink", "article", "cpaInstall"]
    m4_tasks = ["dailyBonus"]
    
    milestone_reward = 0
    m_name = ""
    m_type = ""
    
    if body.task_type in m2_tasks and not user.get("ob_m2_done"):
        user["ob_m2_done"] = True
        milestone_reward = 300
        m_name = "Welcome Bonus: First Social Task"
        m_type = "onboarding_milestone_2"
        user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1
    elif body.task_type in m3_tasks and not user.get("ob_m3_done"):
        user["ob_m3_done"] = True
        milestone_reward = 300
        m_name = "Welcome Bonus: Core Channel Engagement"
        m_type = "onboarding_milestone_3"
        user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1
    elif body.task_type in m4_tasks and not user.get("ob_m4_done"):
        user["ob_m4_done"] = True
        milestone_reward = 300
        m_name = "Welcome Bonus: Retention Streak"
        m_type = "onboarding_milestone_4"
        user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1

    if milestone_reward > 0:
        user["balance"] = float(user.get("balance", 0)) + milestone_reward
        user["earnings"] = float(user.get("earnings", 0)) + milestone_reward
        tx_id = f"TX_OBM_{int(datetime.now(timezone.utc).timestamp())}_{uuid.uuid4().hex[:4]}"
        history.append({
            "id": tx_id,
            "type": m_type,
            "name": m_name,
            "amount": milestone_reward,
            "date": datetime.now(timezone.utc).isoformat(),
            "status": "Paid"
        })
        ledger["grossWc"] = ledger.get("grossWc", 0) + milestone_reward
        ledger["userWc"] = ledger.get("userWc", 0) + milestone_reward

    user["earningsHistory"] = history

    return save_user(user)


@app.post("/api/referrals/credit")
def credit_referral(body: ReferralCreditRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, str]:
    verify_user_active(user)
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
    verify_user_active(user)
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
        otp = str(100000 + int.from_bytes(__import__("os").urandom(3), "big") % 900000)
        return {"success": True, "message": "Mock OTP mode", "otp": otp}

    otp = str(100000 + int.from_bytes(__import__("os").urandom(3), "big") % 900000)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://www.fast2sms.com/dev/bulkV2",
            headers={"authorization": FAST2SMS_API_KEY, "Content-Type": "application/json"},
            json={
                "route": "q",
                "message": f"Your WinWin Pro verification OTP is: {otp}. Do not share this with anyone.",
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
    username_ok = _hmac.compare_digest(body.username, ADMIN_USERNAME)
    password_ok = _hmac.compare_digest(body.password, ADMIN_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return {"token": create_token("admin", "admin")}


@app.post("/api/admin/verify")
def verify_admin_access(body: AdminLoginRequest) -> dict[str, str]:
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


# ── Offerwall Postbacks ───────────────────────────────────────────────────────

import hashlib

@app.get("/api/timewall-postback")
def timewall_postback(request: Request) -> dict[str, Any]:
    params = request.query_params
    userID = params.get("userID") or params.get("userId") or ""
    transactionID = params.get("transactionID") or params.get("transactionId") or ""
    revenue = params.get("revenue", "0")
    currencyAmount = float(params.get("currencyAmount") or params.get("reward") or 0.0)
    hash_val = params.get("hash") or params.get("signature") or ""
    type_val = params.get("type", "credit")

    secret_key = "b6d96ae844a97a6ab08dcd152dedd2ad"
    concat_str = f"{userID}{revenue}{secret_key}"
    expected_hash = hashlib.sha256(concat_str.encode('utf-8')).hexdigest()
    
    if hash_val and hash_val != expected_hash:
        return {"status": "ok", "message": "Ignored: Invalid hash"}


    user = get_user_by_id(userID)
    if not user:
        return {"status": "ok", "message": "Ignored: User not found"}
        
    history = user.get("earningsHistory") or user.get("earningHistory") or []
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    
    if type == "credit":
        if any(h.get("id") == transactionID for h in history):
            return {"status": "ok", "message": "Already credited"}

        user["balance"] = float(user.get("balance", 0)) + currencyAmount
        user["earnings"] = float(user.get("earnings", 0)) + currencyAmount
        
        history.append({
            "id": transactionID,
            "type": "timewall_offer",
            "name": "TimeWall Offer",
            "amount": currencyAmount,
            "date": datetime.now(timezone.utc).isoformat(),
            "status": "Paid"
        })
        ledger["grossWc"] = ledger.get("grossWc", 0) + currencyAmount
        ledger["userWc"] = ledger.get("userWc", 0) + currencyAmount

    elif type_val == "chargeback":
        if any(h.get("id") == f"CB_{transactionID}" for h in history):
            return {"status": "ok", "message": "Already chargebacked"}
            
        user["balance"] = float(user.get("balance", 0)) + currencyAmount
        
        history.append({
            "id": f"CB_{transactionID}",
            "type": "timewall_chargeback",
            "name": "TimeWall Chargeback",
            "amount": currencyAmount,
            "date": datetime.now(timezone.utc).isoformat(),
            "status": "Chargeback"
        })
        ledger["userWc"] = ledger.get("userWc", 0) + currencyAmount

    elif type_val == "hold":
        if any(h.get("id") == f"HOLD_{transactionID}" for h in history):
            return {"status": "ok", "message": "Already on hold"}
        history.append({
            "id": f"HOLD_{transactionID}",
            "type": "timewall_hold",
            "name": "TimeWall Offer (Pending)",
            "amount": currencyAmount,
            "date": datetime.now(timezone.utc).isoformat(),
            "status": "Pending"
        })

    elif type_val == "hold_cancelled":
        history = [h for h in history if h.get("id") != f"HOLD_{transactionID}"]

    user["earningsHistory"] = history
    save_user(user)
    return {"status": "ok"}

