"""SAFE: credentials loaded from environment variables, not hardcoded."""
import os
import requests


def fetch_data(endpoint: str):
    api_key = os.environ["API_KEY"]
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(endpoint, headers=headers)
    return response.json()


def get_db_dsn() -> str:
    host = os.environ.get("DB_HOST", "localhost")
    user = os.environ.get("DB_USER", "app")
    password = os.environ["DB_PASSWORD"]
    return f"postgresql://{user}:{password}@{host}:5432/myapp"
