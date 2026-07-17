import psycopg2

dsn = "dbname=postgres user=postgres.snimtbuwakfqfooazmpt password='vzuLeN8uC$./jV2' host=aws-1-ap-south-1.pooler.supabase.com port=6543"

try:
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()

    cur.execute("DELETE FROM winwin_users WHERE email != 'admin'")
    conn.commit()

    cur.execute("SELECT email FROM winwin_users")
    remaining = cur.fetchall()
    print('Remaining users:', remaining)

    conn.close()
    print("Success")
except Exception as e:
    print("Error:", e)
