"""VULN: CWE-798 — Hardcoded API key and database password in source."""
import requests

API_KEY = "sk-proj-xK9mN2pL8qR4tY7wZ3vJ6hU1cA0dF5gB"
DATABASE_PASSWORD = "Sup3r$ecret_DB_Pass_2024!"


def fetch_data(endpoint):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(endpoint, headers=headers)
    return response.json()


def get_db_dsn():
    return f"postgresql://admin:{DATABASE_PASSWORD}@localhost:5432/myapp"
