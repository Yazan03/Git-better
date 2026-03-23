# SEC001 — Hardcoded secrets
password = "supersecret123"
api_key = "sk-abc123xyz789"
auth_token = "Bearer eyJhbGciOiJIUzI1NiJ9..."

# SEC002 — Dangerous functions
eval("__import__('os').system('rm -rf /')")
exec(open("malicious.py").read())
os.system("cat /etc/passwd")

# SEC004 — SQL injection via string formatting
query = f"SELECT * FROM users WHERE id = {user_input}"
query = "DELETE FROM accounts WHERE user = '%s'" % username