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
from pathlib import Path

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer
from prometheus_client import Counter, Gauge, Histogram

DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "mock_users.json") as f:
    USER_DATA = json.load(f)

_request_counts = defaultdict(list)
_auth_failures = defaultdict(list)
_query_counts = defaultdict(int)

security = HTTPBearer(auto_error=False)

# ── Prometheus Security Metrics ──────────────────────────────

AUTH_FAILURES = Counter(
    "diagnosticassist_auth_failures_total",
    "Total authentication failures",
    ["reason"]
)
MFA_BYPASS_ATTEMPTS = Counter(
    "diagnosticassist_mfa_bypass_attempts_total",
    "Total MFA bypass attempts detected"
)
PHI_LEAKS_DETECTED = Counter(
    "diagnosticassist_phi_leaks_detected_total",
    "Total PHI leak detections in LLM responses"
)
PROMPT_INJECTION_ATTEMPTS = Counter(
    "diagnosticassist_prompt_injection_attempts_total",
    "Total prompt injection attempts detected"
)
ADVERSARIAL_IMAGES_DETECTED = Counter(
    "diagnosticassist_adversarial_images_detected_total",
    "Total adversarial image attacks detected"
)
MODEL_EXTRACTION_ALERTS = Counter(
    "diagnosticassist_model_extraction_alerts_total",
    "Total model extraction attempt alerts"
)
EHR_ISOLATION_VIOLATIONS = Counter(
    "diagnosticassist_ehr_isolation_violations_total",
    "Total cross-network EHR access violation attempts"
)
SECURITY_EVENTS = Counter(
    "diagnosticassist_security_events_total",
    "Total security events by type",
    ["event_type"]
)
HTTP_REQUESTS = Counter(
    "diagnosticassist_http_requests_total",
    "Total HTTP requests",
    ["endpoint", "method", "status"]
)
ACTIVE_SESSIONS = Gauge(
    "diagnosticassist_active_sessions",
    "Currently active authenticated sessions"
)
REQUEST_LATENCY = Histogram(
    "diagnosticassist_request_latency_seconds",
    "Request latency in seconds",
    ["endpoint"]
)


def get_token_data(token: str) -> dict | None:
    return USER_DATA["tokens"].get(token)


def validate_token(token: str) -> dict:
    token_data = get_token_data(token)
    if not token_data:
        AUTH_FAILURES.labels(reason="invalid_token").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return token_data


def check_network_access(user_network: str, requested_network: str) -> bool:
    allowed = user_network == requested_network
    if not allowed:
        EHR_ISOLATION_VIOLATIONS.inc()
        log_security_event(
            "EHR_ISOLATION_VIOLATION",
            user_network,
            f"Attempted access to {requested_network}"
        )
    return allowed


def rate_limit_check(identifier: str, limit: int = 60) -> bool:
    now = time.time()
    window = 60
    _request_counts[identifier] = [
        t for t in _request_counts[identifier]
        if now - t < window
    ]
    if len(_request_counts[identifier]) >= limit:
        return False
    _request_counts[identifier].append(now)
    return True


def check_model_extraction(user_id: str) -> bool:
    _query_counts[user_id] += 1
    if _query_counts[user_id] > 5000:
        MODEL_EXTRACTION_ALERTS.inc()
        log_security_event(
            "POTENTIAL_MODEL_EXTRACTION",
            user_id,
            f"Query count: {_query_counts[user_id]}"
        )
        return False
    return True


def log_auth_failure(ip: str, username: str):
    now = time.time()
    window = 3600
    _auth_failures[ip] = [
        t for t in _auth_failures[ip]
        if now - t < window
    ]
    _auth_failures[ip].append(now)
    AUTH_FAILURES.labels(reason="invalid_credentials").inc()

    failure_count = len(_auth_failures[ip])
    if failure_count >= 50:
        log_security_event(
            "AUTH_SPIKE_DETECTED",
            ip,
            f"{failure_count} failures in last hour"
        )


def log_mfa_bypass(user_id: str):
    MFA_BYPASS_ATTEMPTS.inc()
    log_security_event(
        "MFA_BYPASS_ATTEMPTED",
        user_id,
        "api_client role accessed without MFA"
    )


def log_prompt_injection(user_id: str, prompt: str):
    PROMPT_INJECTION_ATTEMPTS.inc()
    log_security_event(
        "PROMPT_INJECTION_DETECTED",
        user_id,
        f"Injection pattern in prompt: {prompt[:100]}"
    )


def log_adversarial_image(user_id: str, confidence: float):
    ADVERSARIAL_IMAGES_DETECTED.inc()
    log_security_event(
        "ADVERSARIAL_IMAGE_DETECTED",
        user_id,
        f"Model confidence dropped to {confidence:.0%}"
    )


def log_security_event(event_type: str, actor: str, detail: str):
    SECURITY_EVENTS.labels(event_type=event_type).inc()
    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "actor": actor,
        "detail": detail
    }
    print(f"[AUDIT] {entry}")


def scan_for_phi(text: str) -> list[str]:
    from config.settings import PHI_PATTERNS
    found = []
    for pattern in PHI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern)
    return found


def sanitize_response(text: str) -> tuple[str, bool]:
    phi_found = scan_for_phi(text)
    if phi_found:
        PHI_LEAKS_DETECTED.inc()
        log_security_event(
            "PHI_LEAK_DETECTED",
            "llm_interface",
            f"PHI patterns found: {phi_found}"
        )
        return "[RESPONSE BLOCKED: Contains protected health information]", True
    return text, False
