import psycopg2

db_url = 'postgresql://postgres.snimtbuwakfqfooazmpt:vzuLeN8uC$./jV2@aws-1-ap-south-1.pooler.supabase.com:6543/postgres'
conn = psycopg2.connect(db_url)
cur = conn.cursor()

cur.execute("DELETE FROM winwin_users WHERE email != 'admin'")
conn.commit()

cur.execute("SELECT email FROM winwin_users")
remaining = cur.fetchall()
print('Remaining users:', remaining)

conn.close()
