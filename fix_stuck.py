import os
os.environ["DATABASE_URL"] = "postgresql://postgres.snimtbuwakfqfooazmpt:vzuLeN8uC$.%2FjV2@aws-1-ap-south-1.pooler.supabase.com:6543/postgres"

from database import list_all_users, save_user

def fix():
    users = list_all_users()
    fixed_count = 0
    for u in users:
        changed = False
        w_list = u.get("withdrawals", [])
        for w in w_list:
            if w.get("status") == "PENDING" and w.get("amount") == 5999.0:
                print(f"Found stuck withdrawal for user {u['userId']}")
                w["status"] = "REJECTED"
                u["balance"] = float(u.get("balance", 0)) + 5999.0
                
                import uuid
                from datetime import datetime, timezone
                u.setdefault("notifications", []).append({
                    "id": f"notif_{uuid.uuid4().hex[:8]}",
                    "title": "Withdrawal Rejected",
                    "message": "Your withdrawal of 5999.0 ₩ has been rejected and refunded to your balance.",
                    "date": datetime.now(timezone.utc).isoformat(),
                    "read": False
                })
                changed = True
        if changed:
            save_user(u)
            fixed_count += 1
            print(f"Fixed user {u['userId']}")
    print(f"Fixed {fixed_count} users.")

if __name__ == "__main__":
    fix()
