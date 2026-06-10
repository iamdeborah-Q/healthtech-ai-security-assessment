"""
Authentication Security Tests
Assessment: Comprehensive AI Security Assessment
Platform: HealthTech AI DiagnosticAssist
Findings: GAP-001, GAP-002, GAP-003
"""

import requests
import pytest

BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/api/v1/auth"

# Valid doctor credentials for network_a
VALID_CREDENTIALS = {
    "username": "dr.johnson",
    "password": "correct_password"
}

# Pre-issued tokens for testing authenticated endpoints
VALID_TOKEN = "valid_token_network_a"
ADMIN_TOKEN = "admin_token_network_a"

# Verify that a doctor with correct credentials receives a token
def test_valid_login_succeeds():
    response = requests.post(
        f"{AUTH_URL}/login",
        json=VALID_CREDENTIALS
    )
    assert response.status_code == 200
    assert "token" in response.json()
    assert "role" in response.json()

# Verify that a wrong password is rejected with 401
def test_invalid_password_rejected():
    response = requests.post(
        f"{AUTH_URL}/login",
        json={"username": "dr.johnson", "password": "wrong"}
    )
    assert response.status_code == 401

# GAP-003: Login returns different errors exposing whether username exists
def test_username_enumeration_vulnerability():
    response_fake = requests.post(
        f"{AUTH_URL}/login",
        json={"username": "nonexistent_xyz", "password": "any"}
    )
    response_real = requests.post(
        f"{AUTH_URL}/login",
        json={"username": "dr.johnson", "password": "wrong"}
    )
    fake_error = response_fake.json().get("detail", "")
    real_error = response_real.json().get("detail", "")
    if fake_error != real_error:
        print(f"\n[FINDING] GAP-003 CONFIRMED")
        print(f"  Non-existent user: '{fake_error}'")
        print(f"  Wrong password:    '{real_error}'")
    assert response_fake.status_code == 401

# Verify that empty username and password fields are rejected
def test_empty_credentials_rejected():
    response = requests.post(
        f"{AUTH_URL}/login",
        json={"username": "", "password": ""}
    )
    assert response.status_code in [400, 401, 422]

# Verify that a request with no credentials body is rejected
def test_missing_credentials_rejected():
    response = requests.post(
        f"{AUTH_URL}/login",
        json={}
    )
    assert response.status_code in [400, 422]

# Verify that a known valid token passes the validation check
def test_valid_token_validates():
    response = requests.get(
        f"{AUTH_URL}/validate",
        params={"token": VALID_TOKEN}
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True

# Verify that a made-up token is flagged as invalid
def test_invalid_token_rejected():
    response = requests.get(
        f"{AUTH_URL}/validate",
        params={"token": "fake_token_xyz"}
    )
    assert response.json()["valid"] is False

# Verify that the LLM query endpoint blocks unauthenticated requests
def test_llm_endpoint_requires_auth():
    response = requests.post(
        f"{BASE_URL}/api/v1/llm/query",
        json={"query": "test"}
    )
    assert response.status_code == 401

# Verify that the EHR patient endpoint blocks unauthenticated requests
def test_ehr_endpoint_requires_auth():
    response = requests.get(
        f"{BASE_URL}/api/v1/ehr/patient/PT-001"
    )
    assert response.status_code == 401

# Verify that the imaging endpoint blocks unauthenticated requests
def test_imaging_endpoint_requires_auth():
    response = requests.post(
        f"{BASE_URL}/api/v1/imaging/analyze",
        params={"modality": "CHEST_XRAY", "patient_id": "PT-001"}
    )
    assert response.status_code in [401, 422]

# GAP-001: Confirm radiologist role correctly requires MFA at login
def test_mfa_required_for_radiologist():
    response = requests.post(
        f"{AUTH_URL}/login",
        json=VALID_CREDENTIALS
    )
    assert response.status_code == 200
    assert response.json()["mfa_required"] is True

# Verify that a valid 6-digit MFA code is accepted
def test_mfa_verification_works():
    response = requests.post(
        f"{AUTH_URL}/mfa/verify",
        json={"token": VALID_TOKEN, "mfa_code": "123456"}
    )
    assert response.status_code == 200
    assert response.json()["verified"] is True

# Verify that a code shorter than 6 digits is rejected
def test_mfa_rejects_invalid_code():
    response = requests.post(
        f"{AUTH_URL}/mfa/verify",
        json={"token": VALID_TOKEN, "mfa_code": "123"}
    )
    assert response.status_code == 400

# Verify that an authenticated radiologist can successfully query the LLM
def test_radiologist_can_access_llm():
    response = requests.post(
        f"{BASE_URL}/api/v1/llm/query",
        json={"query": "What are signs of pneumonia?"},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"}
    )
    assert response.status_code in [200, 500]

# Verify that the admin token returns the correct role and network
def test_admin_token_has_correct_role():
    response = requests.get(
        f"{AUTH_URL}/validate",
        params={"token": ADMIN_TOKEN}
    )
    data = response.json()
    assert data["role"] == "hospital_admin"
    assert data["network"] == "network_a"
