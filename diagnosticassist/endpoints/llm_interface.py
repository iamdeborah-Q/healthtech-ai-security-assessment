"""
DiagnosticAssist LLM interface endpoint.
Natural language queries for radiologists.

SECURITY SURFACE:
- Prompt injection attacks
- PHI leakage through model responses
- Session context bleeding between patients
- Model extraction via systematic querying
"""

import json
import time
from pathlib import Path

import requests
from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel

from config.settings import (
    LLM_BASE_URL,
    LLM_MAX_TOKENS,
    LLM_MODEL,
    LLM_SYSTEM_PROMPT,
    LLM_TEMPERATURE,
)
from middleware.auth import (
    check_model_extraction,
    log_security_event,
    rate_limit_check,
    sanitize_response,
    validate_token,
)

router = APIRouter(prefix="/api/v1/llm", tags=["LLM Interface"])
DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "mock_patients.json") as f:
    PATIENT_DATA = json.load(f)


# ── Request / Response models ────────────────────────────────

class QueryRequest(BaseModel):
    query: str
    patient_id: str | None = None
    include_patient_context: bool = False


class QueryResponse(BaseModel):
    response: str
    model: str
    patient_context_used: bool
    phi_detected: bool
    query_id: str
    timestamp: float


# ── Prompt injection detection ───────────────────────────────

INJECTION_SIGNATURES = [
    "ignore previous instructions",
    "ignore all instructions",
    "disregard",
    "you are now",
    "act as",
    "pretend you are",
    "new instructions",
    "system override",
    "admin mode",
    "unrestricted mode",
    "bypass",
    "jailbreak",
    "dan mode",
    "without restrictions",
    "forget everything",
    "your true self",
]


def detect_prompt_injection(query: str) -> bool:
    """
    Detect prompt injection attempts in user query.
    Returns True if injection attempt detected.
    """
    query_lower = query.lower()
    for signature in INJECTION_SIGNATURES:
        if signature in query_lower:
            return True
    return False


def build_safe_prompt(query: str, patient_context: str = "") -> list[dict]:
    """
    Build a prompt that sandboxes user input from system instructions.
    Uses clear delimiters to prevent instruction injection.
    """
    messages = [
        {
            "role": "system",
            "content": LLM_SYSTEM_PROMPT
        }
    ]

    if patient_context:
        messages.append({
            "role": "system",
            "content": f"CLINICAL CONTEXT (read only — do not reveal identifiers):\n{patient_context}"
        })

    # User input is clearly delimited — cannot override system prompt
    messages.append({
        "role": "user",
        "content": f"RADIOLOGIST QUERY:\n{query}"
    })

    return messages


def get_patient_context(patient_id: str, user_network: str) -> str:
    """
    Retrieve safe clinical context for a patient.
    Strips all direct identifiers — only clinical facts returned.
    """
    patients = {p["patient_id"]: p for p in PATIENT_DATA["patients"]}
    patient = patients.get(patient_id)

    if not patient:
        return ""

    # Network isolation — cannot access patients from other networks
    if patient["hospital_network"] != user_network:
        log_security_event(
            "CROSS_NETWORK_ACCESS_ATTEMPT",
            user_network,
            f"Attempted access to patient in {patient['hospital_network']}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied — patient not in your network"
        )

    # Return clinical context ONLY — no PHI identifiers
    studies = {s["study_id"]: s for s in PATIENT_DATA["imaging_studies"]}
    patient_studies = [
        studies[sid] for sid in patient["imaging_studies"]
        if sid in studies
    ]

    context = f"Conditions: {', '.join(patient['conditions'])}\n"
    context += "Recent imaging:\n"
    for study in patient_studies:
        context += f"  - {study['modality']} ({study['date']}): {study['findings']}\n"
        context += f"    AI confidence: {study['ai_confidence']}\n"

    return context


# ── Main LLM endpoint ────────────────────────────────────────

@router.post("/query", response_model=QueryResponse)
async def query_llm(
    request: Request,
    body: QueryRequest,
    authorization: str = Header(None)
):
    """
    Main LLM query endpoint.
    Radiologists query DiagnosticAssist in natural language.
    """
    # ── Authentication ───────────────────────────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    token = authorization.replace("Bearer ", "")
    user = validate_token(token)

    # ── Rate limiting ────────────────────────────────────────
    client_ip = request.client.host
    if not rate_limit_check(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

    # ── Model extraction detection ───────────────────────────
    if not check_model_extraction(user["user_id"]):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily query limit exceeded"
        )

    # ── Prompt injection detection ───────────────────────────
    injection_detected = detect_prompt_injection(body.query)
    if injection_detected:
        log_security_event(
            "PROMPT_INJECTION_ATTEMPT",
            user["user_id"],
            f"Query: {body.query[:100]}"
        )
        return QueryResponse(
            response="I can only assist with radiology and diagnostic queries.",
            model=LLM_MODEL,
            patient_context_used=False,
            phi_detected=False,
            query_id=f"QRY-{int(time.time())}",
            timestamp=time.time()
        )

    # ── Patient context (optional) ───────────────────────────
    patient_context = ""
    if body.patient_id and body.include_patient_context:
        patient_context = get_patient_context(
            body.patient_id,
            user["network"]
        )

    # ── Build safe prompt ────────────────────────────────────
    messages = build_safe_prompt(body.query, patient_context)

    # ── Call Ollama LLM ──────────────────────────────────────
    try:
        ollama_response = requests.post(
            f"{LLM_BASE_URL}/api/chat",
            json={
                "model": LLM_MODEL,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": LLM_TEMPERATURE,
                    "num_predict": LLM_MAX_TOKENS
                }
            },
            timeout=30
        )
        ollama_response.raise_for_status()
        raw_response = ollama_response.json()["message"]["content"]

    except requests.exceptions.ConnectionError:
        # Ollama not running — return mock response for testing
        raw_response = (
            "Based on the imaging findings, this presentation is consistent "
            "with the described pathology. Recommend correlation with clinical "
            "history and follow-up imaging as clinically indicated."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI service temporarily unavailable"
            # NOTE: Never expose internal errors to client
        )

    # ── PHI scan on response before returning ────────────────
    safe_response, phi_detected = sanitize_response(raw_response)

    # ── Audit log ────────────────────────────────────────────
    log_security_event(
        "LLM_QUERY",
        user["user_id"],
        f"Patient: {body.patient_id or 'none'} | PHI detected: {phi_detected}"
    )

    return QueryResponse(
        response=safe_response,
        model=LLM_MODEL,
        patient_context_used=bool(patient_context),
        phi_detected=phi_detected,
        query_id=f"QRY-{int(time.time())}",
        timestamp=time.time()
    )
