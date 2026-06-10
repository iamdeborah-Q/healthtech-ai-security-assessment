"""
DiagnosticAssist authentication endpoint.
Login, token validation, MFA verification.

SECURITY SURFACE:
- Brute force attacks on login
- MFA bypass attempts
- Token enumeration
- Privilege escalation via role manipulation
"""

import json
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from middleware.auth import log_auth_failure, log_security_event

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "mock_users.json") as f:
    USER_DATA = json.load(f)


# ── Request / Response models ────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    role: str
    network: str
    mfa_required: bool
    expires_in: int


class MFAVerifyRequest(BaseModel):
    token: str
    mfa_code: str


class TokenValidateResponse(BaseModel):
    valid: bool
    user_id: str
    role: str
    network: str


# ── Auth endpoints ───────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(request: Request, body: LoginRequest):
    """
    Authenticate user and return JWT token.
    Rate limited — tracks brute force attempts.
    """
    client_ip = request.client.host

    # Find user by username
    user = next(
        (u for u in USER_DATA["users"]
         if u["username"] == body.username),
        None
    )

    # GAP-003: Error message leaks whether username exists
    # Should return generic "Invalid credentials" for both cases
    if not user:
        log_auth_failure(client_ip, body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"      # SECURITY GAP — reveals user existence
        )

    # Mock password check — in production use bcrypt
    if body.password != "correct_password":
        log_auth_failure(client_ip, body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    # Find token for this user
    user_token = next(
        (token for token, data in USER_DATA["tokens"].items()
         if data["user_id"] == user["user_id"]),
        None
    )

    if not user_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

    log_security_event(
        "LOGIN_SUCCESS",
        user["user_id"],
        f"IP: {client_ip} | Role: {user['role']}"
    )

    return LoginResponse(
        token=user_token,
        role=user["role"],
        network=user["hospital_network"],
        mfa_required=user["mfa_enabled"],
        expires_in=3600
    )


@router.post("/mfa/verify")
async def verify_mfa(request: Request, body: MFAVerifyRequest):
    """
    Verify MFA code for privileged access.
    Required for radiologist and hospital_admin roles.
    GAP-001: api_client role bypasses MFA entirely.
    """
    token_data = USER_DATA["tokens"].get(body.token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    # Mock MFA — accept any 6-digit code for testing
    if len(body.mfa_code) != 6 or not body.mfa_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA code must be 6 digits"
        )

    log_security_event(
        "MFA_VERIFIED",
        token_data["user_id"],
        f"Role: {token_data['role']}"
    )

    return {"verified": True, "message": "MFA verification successful"}


@router.get("/validate", response_model=TokenValidateResponse)
async def validate_token_endpoint(token: str):
    """
    Validate an authentication token.
    Used by other services to verify identity.
    """
    token_data = USER_DATA["tokens"].get(token)
    if not token_data:
        return TokenValidateResponse(
            valid=False,
            user_id="",
            role="",
            network=""
        )

    return TokenValidateResponse(
        valid=True,
        user_id=token_data["user_id"],
        role=token_data["role"],
        network=token_data["network"]
    )


@router.post("/logout")
async def logout(request: Request, token: str):
    """Invalidate user session."""
    token_data = USER_DATA["tokens"].get(token)
    if token_data:
        log_security_event(
            "LOGOUT",
            token_data["user_id"],
            f"Session ended"
        )
    return {"message": "Logged out successfully"}
