import hashlib
import random
import time
import uuid
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
    TIMEWALL_SECRET_KEY,
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
    delete_user,
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


from typing import Optional, Dict

class WithdrawalRequest(BaseModel):
    amount: float
    method: str
    account_details: str
    location_data: Optional[Dict] = None

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
    earnings: float | None = None
    earningsHistory: list | None = None
    remoteNotifications: list | None = None


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
    pincode: str | None = None
    location_lat: float | None = None
    location_lng: float | None = None
    isFinalStep: bool = False


class UserMeUpdateRequest(BaseModel):
    username: str | None = None
    clearNotifications: bool | None = None
    pincode: str | None = None
    location_lat: float | None = None
    location_lng: float | None = None
    location_city: str | None = None


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


@app.get("/api/cpa-apps")
def get_cpa_apps() -> dict[str, Any]:
    cfg = get_content_config() or {}
    return {"status": "ok", "apps": cfg.get("cpaApps", [])}


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
    hist1 = user.get("earningsHistory") or []
    hist2 = user.get("earningHistory") or []
    if isinstance(hist1, dict): hist1 = []
    if isinstance(hist2, dict): hist2 = []
    history = hist1 + hist2
    user.pop("earningHistory", None)
    def _ts(e):
        t = e.get("timestamp") or e.get("date") or e.get("at")
        if t is None:
            return None
        if isinstance(t, (int, float)):
            return datetime.fromtimestamp(t / 1000 if t > 1e12 else t, tz=timezone.utc)
        return datetime.fromisoformat(t.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    user["todays_earnings"] = sum(e.get("amount", 0) for e in history if _ts(e) and _ts(e) >= today_start and e.get("amount", 0) > 0)
    user["last_30_days"] = sum(e.get("amount", 0) for e in history if _ts(e) and _ts(e) >= thirty_days_ago and e.get("amount", 0) > 0)
    ledger = user.get("ledger", {})
    user["earnings"] = ledger.get("grossWc", user.get("balance", 0))
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
    if body.clearNotifications:
        user["notifications"] = []
    if body.pincode is not None:
        user["pincode"] = body.pincode
    if body.location_lat is not None:
        user["location_lat"] = body.location_lat
    if body.location_lng is not None:
        user["location_lng"] = body.location_lng
    if body.location_city is not None:
        user["location_city"] = body.location_city
    return save_user(user)


@app.post("/api/users/upgrade")
def upgrade_to_pro(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    cfg = get_content_config() or {}
    try:
        cost = int(cfg.get("vipCost", 499))
    except (ValueError, TypeError):
        cost = 499

    
    if user.get("isVip"):
        raise HTTPException(status_code=400, detail="Already a PRO user")
        
    if float(user.get("balance", 0)) < cost:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Need {cost} ₩.")
        
    if "earnings" not in user:
        user["earnings"] = user.get("balance", 0)
    
    user["balance"] = float(user.get("balance", 0)) - cost
    user["isVip"] = True
    
    history = user.get("earningsHistory") or []
    history.append({
        "type": "UPGRADE_FEE",
        "amount": -cost,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "PRO Upgrade"
    })
    user["earningsHistory"] = history
    
    save_user(user)
    return {"status": "success", "message": "Upgraded to PRO successfully"}




@app.post("/api/users/onboarding")
def complete_onboarding(body: OnboardingRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    if user.get("onboardingCompleted"):
        return {"message": "Already onboarded", "user": user}

    reward = 0
    if body.name and not user.get("name"):
        user["username"] = body.name
        user["name"] = body.name
        reward += 50
    if body.age and not user.get("age"):
        user["age"] = body.age
        reward += 50
    if body.gender and not user.get("gender"):
        user["gender"] = body.gender
        reward += 50
    if body.pincode and not user.get("pincode"):
        user["pincode"] = body.pincode
        reward += 50
        
    if body.location_lat is not None:
        user["location_lat"] = body.location_lat
    if body.location_lng is not None:
        user["location_lng"] = body.location_lng

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
    "videoAd": 30,
    "articleRead": 30,
    "directLink": 30,
    "socialFollow": 10,
    "googleGig": 200,
    "webMicroGig": 200,
    "casualGame": 5,
    "socialMicro": 15,
    "customTask": 300,
    "cpaCPL": 200,
}


def process_milestones(user: dict, task_type: str):
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    hist1 = user.get("earningsHistory") or []
    hist2 = user.get("earningHistory") or []
    if isinstance(hist1, dict): hist1 = []
    if isinstance(hist2, dict): hist2 = []
    history = hist1 + hist2
    user.pop("earningHistory", None)
    if isinstance(history, dict): history = []
    
    milestone_reward = 0
    m_name = ""
    m_type = ""
    
    if task_type in ["articleRead", "article"]:
        user["articles_count"] = user.get("articles_count", 0) + 1
        if user["articles_count"] >= 2 and not user.get("ob_m2_done"):
            user["ob_m2_done"] = True
            milestone_reward = 200
            m_name = "Welcome Bonus: Complete 2 Articles"
            m_type = "onboarding_milestone_2"
            user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1
            
    elif task_type in ["shortlink"]:
        user["shortlinks_count"] = user.get("shortlinks_count", 0) + 1
        if user["shortlinks_count"] >= 2 and not user.get("ob_m3_done"):
            user["ob_m3_done"] = True
            milestone_reward = 200
            m_name = "Welcome Bonus: Complete 2 Shortlinks"
            m_type = "onboarding_milestone_3"
            user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1

    elif task_type == "lottery_ticket":
        user["lottery_buy_count"] = user.get("lottery_buy_count", 0) + 1
        if user["lottery_buy_count"] >= 2 and not user.get("ob_m4_done"):
            user["ob_m4_done"] = True
            milestone_reward = 200
            m_name = "Welcome Bonus: Buy 2 Lottery Tickets"
            m_type = "onboarding_milestone_4"
            user["onboarding_stage"] = user.get("onboarding_stage", 0) + 1

    elif task_type in ["dailyBonus"]:
        if not user.get("ob_m5_done"):
            user["ob_m5_done"] = True
            milestone_reward = 200
            m_name = "Welcome Bonus: Claim Daily Streak"
            m_type = "onboarding_milestone_5"
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

@app.post("/api/tasks/complete")
def complete_task(body: TaskCompleteRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)

    if body.task_type == "dailyBonus":
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        last_claim = user.get("lastDailyClaimDate", "")
        if last_claim == today_str:
            raise HTTPException(status_code=400, detail="Already claimed today")
        
        try:
            last_date = datetime.strptime(last_claim, "%Y-%m-%d").date()
            today_date = datetime.strptime(today_str, "%Y-%m-%d").date()
            if (today_date - last_date).days == 1:
                streak = user.get("dailyStreak", 0) + 1
            else:
                streak = 1
        except Exception:
            streak = 1
            
        if streak > 7:
            streak = 1
            
        user["dailyStreak"] = streak
        user["lastDailyClaimDate"] = today_str
        
        if streak == 1: reward = 50
        elif streak == 2: reward = 100
        elif streak == 3: reward = 150
        elif streak == 4: reward = 200
        elif streak == 5: reward = 300
        elif streak == 6: reward = 400
        elif streak == 7: 
            reward = random.randint(400, 600)
        else: reward = 50
        
        is_vip = user.get("isVip", False)
        if not is_vip:
            reward = int(reward / 2)
        
        user["balance"] = float(user.get("balance", 0)) + reward
        ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
        ledger["grossWc"] = ledger.get("grossWc", 0) + reward
        ledger["userWc"] = ledger.get("userWc", 0) + reward

        hist1 = user.get("earningsHistory") or []
        hist2 = user.get("earningHistory") or []
        if isinstance(hist1, dict): hist1 = []
        if isinstance(hist2, dict): hist2 = []
        history = hist1 + hist2
        user.pop("earningHistory", None)
        if isinstance(history, dict): history = []
        history.append({"task": "dailyBonus", "amount": reward, "at": datetime.now(timezone.utc).isoformat()})
        user["earningsHistory"] = history
        user["todays_earnings"] = user.get("todays_earnings", 0) + reward
        user["last_30_days"] = user.get("last_30_days", 0) + reward
        # Safely increment lifetime earnings
        current_earnings = user.get("earnings", user.get("balance", 0))
        user["earnings"] = current_earnings + reward
        user["lifetimeEarnings"] = user.get("earnings")
        
        process_milestones(user, "dailyBonus")
        
        saved_user = save_user(user)
        saved_user["_latestReward"] = reward
        return saved_user

    if body.task_type == "lottery_ticket":
        cycle_id = body.metadata.get("cycleId")
        if user.get("lotteryCycleId") != cycle_id:
            user["lotteryTickets"] = 0
            user["lotteryCycleId"] = cycle_id

        is_vip = user.get("isVip", False)
        max_tickets = 20 if is_vip else 6
        if user.get("lotteryTickets", 0) >= max_tickets:
            raise HTTPException(status_code=400, detail=f"Maximum tickets ({max_tickets}) reached for this week.")

        if float(user.get("balance", 0.0)) < 100:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        user["balance"] = float(user.get("balance", 0.0)) - 100
        user["lotteryTickets"] = user.get("lotteryTickets", 0) + 1
        process_milestones(user, body.task_type)
        return save_user(user)

    reward = TASK_REWARDS.get(body.task_type)
    if body.task_type in ["articleRead", "article"]:
        # Try to fetch dynamic config
        config = get_content_config() or {}
        dynamic_reward = config.get("articleReward")
        if dynamic_reward is not None:
            try:
                reward = float(dynamic_reward)
            except:
                pass

    if reward is None:
        raise HTTPException(status_code=400, detail=f"Unknown task type: {body.task_type}")
    if reward <= 0:
        raise HTTPException(status_code=400, detail="Invalid reward amount.")

    user["balance"] = float(user.get("balance", 0)) + reward
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    ledger["grossWc"] = ledger.get("grossWc", 0) + reward
    ledger["userWc"] = ledger.get("userWc", 0) + reward
    
    if body.task_type == "videoAd":
        user["videoAdsCompleted"] = user.get("videoAdsCompleted", 0) + 1
    elif body.task_type in ["articleRead", "article"]:
        user["completed_articles_count"] = user.get("completed_articles_count", 0) + 1
    elif body.task_type in ["directLink", "shortlink"]:
        user["directLinksCompleted"] = user.get("directLinksCompleted", 0) + 1
    elif body.task_type in ["socialFollow", "socialMicro"]:
        user["socialTasksCompleted"] = user.get("socialTasksCompleted", 0) + 1
    elif body.task_type in ["cpaCPL", "appInstall", "googleGig", "webMicroGig", "casualGame"]:
        user["completed_app_installs"] = user.get("completed_app_installs", 0) + 1

    hist1 = user.get("earningsHistory") or []
    hist2 = user.get("earningHistory") or []
    if isinstance(hist1, dict): hist1 = []
    if isinstance(hist2, dict): hist2 = []
    history = hist1 + hist2
    user.pop("earningHistory", None)
    if isinstance(history, dict):
        history = []
    history.append({"task": body.task_type, "amount": reward, "at": datetime.now(timezone.utc).isoformat()})
    user["earningsHistory"] = history
    
    user["todays_earnings"] = user.get("todays_earnings", 0) + reward
    user["last_30_days"] = user.get("last_30_days", 0) + reward
    
    current_earnings = user.get("earnings", user.get("balance", 0))
    # If the current balance is somehow larger (e.g. from admin add), we can sync it
    if user.get("balance", 0) > current_earnings:
        current_earnings = user.get("balance", 0) - reward # Base before this reward
        if current_earnings < 0: current_earnings = 0
        
    user["earnings"] = current_earnings + reward
    user["lifetimeEarnings"] = user.get("earnings")
    
    process_milestones(user, body.task_type)
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
        ledger = referrer.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
        ledger["grossWc"] = ledger.get("grossWc", 0) + added
        ledger["refWc"] = ledger.get("refWc", 0) + added
        
        hist1 = referrer.get("earningsHistory") or []
        hist2 = referrer.get("earningHistory") or []
        if isinstance(hist1, dict): hist1 = []
        if isinstance(hist2, dict): hist2 = []
        history = hist1 + hist2
        referrer.pop("earningHistory", None)
        if isinstance(history, dict): history = []
        
        history.append({
            "task": "referralBonus",
            "amount": added,
            "at": datetime.now(timezone.utc).isoformat()
        })
        referrer["earningsHistory"] = history

    save_user(referrer)
    return {"status": "credited", "added": str(added)}


@app.post("/api/withdrawals")
def submit_withdrawal(body: WithdrawalRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    verify_user_active(user)
    cfg = get_content_config() or {}
    try:
        min_redeem = int(cfg.get("minRedeem", MIN_REDEEM_WC))
    except (ValueError, TypeError):
        min_redeem = MIN_REDEEM_WC
        
    if body.amount < min_redeem:
        raise HTTPException(status_code=400, detail=f"Minimum redemption is {min_redeem} WinCash.")
    if float(user.get("balance", 0)) < body.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance.")

    user["balance"] = float(user["balance"]) - body.amount
    
    fee = round(body.amount * 0.024, 2)
    net_amount = body.amount - fee
    
    withdrawal = create_withdrawal(user["userId"], net_amount, body.method, body.account_details)
    withdrawal["gross_amount"] = body.amount
    withdrawal["fee"] = fee
    withdrawal["net_amount"] = net_amount
    
    user.setdefault("withdrawals", []).append(withdrawal)
    save_user(user)
    return {"withdrawal": withdrawal, "user": user}


# ── OTP ──────────────────────────────────────────────────────────────────────

@app.post("/api/otp/send")
async def send_otp(body: OtpRequest) -> dict[str, Any]:
    if not FAST2SMS_API_KEY:
        # In mock mode, log OTP server-side only — never return to client
        otp = str(100000 + int.from_bytes(__import__("os").urandom(3), "big") % 900000)
        print(f"[MOCK OTP] Phone: {body.phone}, OTP: {otp}")
        return {"success": True, "message": "OTP sent (mock mode)"}

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
    if body.earnings is not None:
        user["earnings"] = body.earnings
        user["lifetimeEarnings"] = body.earnings
        ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
        ledger["grossWc"] = body.earnings
    if body.earningsHistory is not None:
        user["earningsHistory"] = body.earningsHistory
    if body.remoteNotifications is not None:
        user.setdefault("notifications", []).extend(body.remoteNotifications)
    return save_user(user)


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user_endpoint(user_id: str, _: dict[str, Any] = Depends(get_admin)) -> dict[str, str]:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    delete_user(user_id)
    return {"status": "success", "message": "User deleted"}


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
    if result.get("_resolved"):
        raise HTTPException(status_code=400, detail="Withdrawal is already resolved (PAID or REJECTED) and cannot be modified again.")
        
    user_id = result["userId"]
    user = get_user_by_id(user_id)
    if user:
        w_list = user.get("withdrawals", [])
        amount_to_refund = result["amount"]
        
        for w in w_list:
            if w.get("id") == wid:
                w["status"] = body.status
                amount_to_refund = w.get("net_amount", result["amount"])
                break
                
        if body.status == "REJECTED":
            user["balance"] = float(user.get("balance", 0)) + amount_to_refund
            user.setdefault("notifications", []).append({
                "id": f"notif_{uuid.uuid4().hex[:8]}",
                "title": "Withdrawal Rejected",
                "message": f"Your withdrawal of {amount_to_refund} ₩ has been rejected and refunded to your balance.",
                "date": datetime.now(timezone.utc).isoformat(),
                "read": False
            })
        elif body.status == "PAID":
            user.setdefault("notifications", []).append({
                "id": f"notif_{uuid.uuid4().hex[:8]}",
                "title": "Withdrawal Paid",
                "message": "Your withdrawal request has been successfully paid out!",
                "date": datetime.now(timezone.utc).isoformat(),
                "read": False
            })
            
        save_user(user)
        
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


@app.get("/api/timewall-postback")
def timewall_postback(request: Request) -> dict[str, Any]:
    params = request.query_params
    userID = params.get("userID") or params.get("userId") or ""
    transactionID = params.get("transactionID") or params.get("transactionId") or ""
    revenue = params.get("revenue", "0")
    currencyAmount = float(params.get("currencyAmount") or params.get("reward") or 0.0)
    hash_val = params.get("hash") or params.get("signature") or ""
    type_val = params.get("type", "credit")

    secret_key = TIMEWALL_SECRET_KEY
    # Try common MD5 concatenation patterns used by Offerwalls
    hash1 = hashlib.md5(f"{userID}{revenue}{secret_key}".encode('utf-8')).hexdigest()
    hash2 = hashlib.md5(f"{userID}{transactionID}{revenue}{secret_key}".encode('utf-8')).hexdigest()
    hash3 = hashlib.md5(f"{userID}{transactionID}{currencyAmount}{secret_key}".encode('utf-8')).hexdigest()
    
    # We also check sha256 just in case
    hash4 = hashlib.sha256(f"{userID}{revenue}{secret_key}".encode('utf-8')).hexdigest()

    if hash_val and hash_val not in [hash1, hash2, hash3, hash4]:
        print(f"TimeWall signature mismatch! Got: {hash_val}")
        raise HTTPException(status_code=403, detail="Invalid postback signature")

    user = get_user_by_id(userID)
    if not user:
        return {"status": "ok", "message": "Ignored: User not found"}
        
    hist1 = user.get("earningsHistory") or []
    hist2 = user.get("earningHistory") or []
    if isinstance(hist1, dict): hist1 = []
    if isinstance(hist2, dict): hist2 = []
    history = hist1 + hist2
    user.pop("earningHistory", None)
    ledger = user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
    
    if type_val == "credit":
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
            
        user["balance"] = float(user.get("balance", 0)) - currencyAmount
        
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

# ── Automated Lottery System ────────────────────────────────────────────────

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

def get_current_cycle_id() -> str:
    from datetime import datetime as dt, timedelta, timezone
    now = dt.now(timezone.utc)
    day = now.weekday()
    diff_to_monday = -6 if day == 6 else (0 - day)
    last_monday = now + timedelta(days=diff_to_monday)
    return f"{last_monday.year}-{last_monday.month}-{last_monday.day}"

def perform_automated_draw():
    cycle_id = get_current_cycle_id()
    users = list_all_users()
    tickets = []
    
    for u in users:
        history = u.get("earningsHistory", [])
        if isinstance(history, list) and any(f"Lottery Win ({cycle_id})" in h.get("type", "") for h in history if isinstance(h, dict)):
            return # Already drawn for this cycle
        
        u_cycle = u.get("lotteryCycleId")
        u_tickets = u.get("lotteryTickets", 0)
        
        if u_cycle == cycle_id and u_tickets > 0:
            is_pro = u.get("isVip", False)
            for _ in range(u_tickets):
                tickets.append((u.get("email"), is_pro))
                
    if not tickets:
        return

    pool = len(tickets) * 100
    weighted_pool = []
    for email, is_pro in tickets:
        if email:
            weight = 70 if is_pro else 30
            weighted_pool.extend([email] * weight)

    unique_winners = []
    num_winners = min(10, len(set([t[0] for t in tickets if t[0]])))

    if not weighted_pool or num_winners == 0:
        return

    while len(unique_winners) < num_winners:
        winner = random.choice(weighted_pool)
        if winner not in unique_winners:
            unique_winners.append(winner)

    prize_per_winner = int(pool / num_winners)

    for i, email in enumerate(unique_winners):
        winner_user = next((u for u in users if u.get("email") == email), None)
        if winner_user:
            balance = float(winner_user.get("balance", 0.0))
            winner_user["balance"] = balance + prize_per_winner
            ledger = winner_user.setdefault("ledger", {"grossWc": 0, "userWc": 0, "refWc": 0, "serverWc": 0, "profitWc": 0})
            ledger["grossWc"] = ledger.get("grossWc", 0) + prize_per_winner
            ledger["serverWc"] = ledger.get("serverWc", 0) + prize_per_winner
            
            history = winner_user.get("earningsHistory", [])
            if not isinstance(history, list):
                history = []
            history.insert(0, {
                "id": f"{int(time.time())}_{i}",
                "type": f"Lottery Win ({cycle_id}) Rank {i+1}",
                "amount": prize_per_winner,
                "date": datetime.now(timezone.utc).isoformat()
            })
            winner_user["earningsHistory"] = history
            winner_user.setdefault("notifications", []).append({
                "id": f"notif_lottery_{int(time.time())}_{i}",
                "title": f"Lottery Win! (Rank {i+1})",
                "message": f"Congratulations! You won {prize_per_winner} ₩ in the lottery!",
                "date": datetime.now(timezone.utc).isoformat(),
                "read": False
            })
            try:
                save_user(winner_user)
            except Exception as e:
                print(f"Error saving user {email}: {e}")

scheduler = BackgroundScheduler()
# Run weekly on Sunday night at 23:59 so Monday gets a new cycle ID and draw is finished.
scheduler.add_job(perform_automated_draw, CronTrigger(day_of_week='sun', hour=23, minute=59))
scheduler.start()
