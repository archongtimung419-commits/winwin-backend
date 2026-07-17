import requests

API_URL = 'https://my-backend-0akx.onrender.com'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'change-me'

# Login
r = requests.post(f"{API_URL}/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
if r.status_code != 200:
    print("Login failed:", r.text)
    exit(1)

token = r.json().get("token")
headers = {"Authorization": f"Bearer {token}"}

# Get users
r = requests.get(f"{API_URL}/api/admin/users", headers=headers)
if r.status_code != 200:
    print("Failed to get users:", r.text)
    exit(1)

users = r.json()
print(f"Found {len(users)} users.")

deleted = 0
for u in users:
    if u["email"] == "admin":
        continue
    # Delete user
    res = requests.delete(f"{API_URL}/api/admin/users/{u['id']}", headers=headers)
    if res.status_code == 200:
        deleted += 1
    else:
        print(f"Failed to delete {u['email']}: {res.text}")

print(f"Deleted {deleted} users successfully.")
