import os
from dotenv import load_dotenv

load_dotenv()
from database import get_conn

with get_conn() as conn:
    conn.execute("DELETE FROM users WHERE email != 'admin'")
    conn.commit()
    users = conn.execute("SELECT email FROM users").fetchall()
    print("Remaining users:", [u["email"] for u in users])
