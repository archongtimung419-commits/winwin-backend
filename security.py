import hashlib
import hmac
import json
from typing import Any


def calculate_signature(user_id: str, balance: float, is_vip: bool, account_status: str, daily_streak: int, salt: str) -> str:
    raw = f"{user_id}|{float(balance):.2f}|{is_vip}|{account_status}|{daily_streak}|{salt}"
    return hashlib.sha256(raw.encode()).hexdigest()


def calculate_hmac(user_id: str, balance: float, is_vip: bool, daily_streak: int, key: str, integrity: str) -> str:
    message = f"HMAC|{user_id}|{int(balance)}|{is_vip}|{daily_streak}|{integrity}"
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def freeze_guard(balance: float, daily_streak: int, is_vip: bool, account_status: str) -> str:
    payload = {
        "_frozen_balance": balance,
        "_frozen_streak": daily_streak,
        "_frozen_vip": is_vip,
        "_frozen_status": account_status,
    }
    return json.dumps(payload, separators=(",", ":"))


def god_mode_sign(user_id: str, balance: float, is_vip: bool, account_status: str, daily_streak: int, salt: str, hmac_key: str) -> dict[str, str]:
    return {
        "dataSignature": calculate_signature(user_id, balance, is_vip, account_status, daily_streak, salt),
        "hmacSignature": calculate_hmac(user_id, balance, is_vip, daily_streak, hmac_key, "function_guard_v2_sealed"),
        "freezeGuard": freeze_guard(balance, daily_streak, is_vip, account_status),
    }


def god_mode_verify(user: dict[str, Any], salt: str, hmac_key: str) -> tuple[bool, int | None]:
    computed = calculate_signature(
        user["userId"], user["balance"], user.get("isVip", False),
        user.get("accountStatus", "ACTIVE"), user.get("dailyStreak", 1), salt
    )
    if user.get("dataSignature") and computed != user["dataSignature"]:
        return False, 1

    computed_hmac = calculate_hmac(
        user["userId"], user["balance"], user.get("isVip", False),
        user.get("dailyStreak", 1), hmac_key, "function_guard_v2_sealed"
    )
    if user.get("hmacSignature") and computed_hmac != user["hmacSignature"]:
        return False, 2

    if user.get("freezeGuard"):
        try:
            frozen = json.loads(user["freezeGuard"])
            if (
                frozen.get("_frozen_balance") != user["balance"]
                or frozen.get("_frozen_streak") != user.get("dailyStreak")
                or frozen.get("_frozen_vip") != user.get("isVip")
                or frozen.get("_frozen_status") != user.get("accountStatus")
            ):
                return False, 3
        except json.JSONDecodeError:
            return False, 3

    return True, None
