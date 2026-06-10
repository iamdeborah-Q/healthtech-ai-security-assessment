import requests
import pytest

BASE_URL = "http://localhost:8000"

def test_app_is_running():
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200

def test_unauthenticated_request_blocked():
    response = requests.get(
        f"{BASE_URL}/api/v1/ehr/patient/PT-001"
    )
    assert response.status_code == 401

def test_llm_requires_auth():
    response = requests.post(
        f"{BASE_URL}/api/v1/llm/query",
        json={"query": "test"}
    )
    assert response.status_code == 401

def test_login_endpoint_exists():
    response = requests.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": "test", "password": "test"}
    )
    assert response.status_code in [200, 401]
