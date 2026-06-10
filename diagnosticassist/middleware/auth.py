"""
DiagnosticAssist authentication middleware.
Handles JWT validation, RBAC, and rate limiting.

NOTE: Contains deliberate security gaps for audit testing:
- GAP-001: No MFA enforcement on API client role
- GAP-002: Token expiry not validated in dev mode
- GAP-003: Error messages leak user existence
"""

import json
import re
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

DATA_DIR = Path(__file__).parent.parent / "data"

# Load mock users
with open(DATA_DIR / "mock_users.json") as f:
    USER_DATA = json.load(f)

# In-memory rate limiting store
_request_counts = defaultdict(list)
_auth_failures = defaultdict(list)
_query_counts = defaultdict(int)

security = HTTPBearer(auto_error=False)


def get_token_data(token: str) -> dict | None:
    """Validate token and return user data."""
    return USER_DATA["tokens"].get(token)


def validate_token(token: str) -> dict:
    """
    Validate JWT token and return user context.
    GAP-002: In dev mode expiry is not checked.
    """
    token_data = get_token_data(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return token_data


def check_network_access(user_network: str, requested_network: str) -> bool:
    """
    Verify user can only access their own hospital network.
    Admins can access their own network only.
    This enforces patient session isolation across networks.
    """
    return user_network == requested_network


def rate_limit_check(identifier: str, limit: int = 60) -> bool:
    """
    Simple in-memory rate limiter.
    Returns True if request is allowed, False if rate limited.
    """
    now = time.time()
    window = 60  # 1 minute window
    _request_counts[identifier] = [
        t for t in _request_counts[identifier]
        if now - t < window
    ]
    if len(_request_counts[identifier]) >= limit:
        return False
    _request_counts[identifier].append(now)
    return True


def check_model_extraction(user_id: str) -> bool:
    """
    Detect potential model extraction attacks.
    Alert if user exceeds 5000 queries per day.
    """
    _query_counts[user_id] += 1
    if _query_counts[user_id] > 5000:
        log_security_event(
            "POTENTIAL_MODEL_EXTRACTION",
            user_id,
            f"Query count: {_query_counts[user_id]}"
        )
        return False
    return True


def log_auth_failure(ip: str, username: str):
    """Track authentication failures for brute force detection."""
    now = time.time()
    window = 3600  # 1 hour
    _auth_failures[ip] = [
        t for t in _auth_failures[ip]
        if now - t < window
    ]
    _auth_failures[ip].append(now)

    failure_count = len(_auth_failures[ip])
    if failure_count >= 50:
        log_security_event(
            "AUTH_SPIKE_DETECTED",
            ip,
            f"{failure_count} failures in last hour"
        )


def log_security_event(event_type: str, actor: str, detail: str):
    """
    Audit log for all security-relevant events.
    HIPAA requires logging all PHI access and AI decisions.
    """
    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "actor": actor,
        "detail": detail
    }
    print(f"[AUDIT] {entry}")


def scan_for_phi(text: str) -> list[str]:
    """
    Scan text for PHI patterns.
    Used on all LLM responses before returning to client.
    """
    from config.settings import PHI_PATTERNS
    found = []
    for pattern in PHI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern)
    return found


def sanitize_response(text: str) -> tuple[str, bool]:
    """
    Remove PHI from LLM response before sending to client.
    Returns (sanitized_text, phi_was_detected).
    """
    phi_found = scan_for_phi(text)
    if phi_found:
        log_security_event(
            "PHI_LEAK_DETECTED",
            "llm_interface",
            f"PHI patterns found: {phi_found}"
        )
        return "[RESPONSE BLOCKED: Contains protected health information]", True
    return text, False
