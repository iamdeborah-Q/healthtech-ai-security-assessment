"""
DiagnosticAssist EHR integration endpoint.
Mock FHIR R4 interface for Epic, Oracle Health, Allscripts.

SECURITY SURFACE:
- Cross-network patient data access
- PHI exposure via API responses
- Session bleeding between hospital networks
- BAA compliance gaps (network_c unsigned)
"""

import json
import time
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel

from config.settings import EHR_SYSTEMS
from middleware.auth import (
    check_network_access,
    log_security_event,
    validate_token,
)

router = APIRouter(prefix="/api/v1/ehr", tags=["EHR Integration"])
DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "mock_patients.json") as f:
    PATIENT_DATA = json.load(f)


# ── Response models ──────────────────────────────────────────

class PatientSummary(BaseModel):
    patient_id: str
    hospital_network: str
    conditions: list[str]
    active_studies: int
    last_visit: str | None = None


class ImagingStudySummary(BaseModel):
    study_id: str
    modality: str
    date: str
    findings: str
    ai_confidence: float


class EHRConnectionStatus(BaseModel):
    network: str
    vendor: str
    connected: bool
    baa_signed: bool
    fhir_version: str = "R4"


# ── Helper functions ─────────────────────────────────────────

def get_patient_by_id(patient_id: str) -> dict | None:
    """Look up patient by ID in mock data."""
    for patient in PATIENT_DATA["patients"]:
        if patient["patient_id"] == patient_id:
            return patient
    return None


def get_studies_for_patient(patient_id: str) -> list[dict]:
    """Get all imaging studies for a patient."""
    return [
        s for s in PATIENT_DATA["imaging_studies"]
        if s["patient_id"] == patient_id
    ]


def check_baa_compliance(network: str) -> bool:
    """
    Verify BAA is signed before allowing PHI access.
    HIPAA requires signed BAA with all covered entities.
    GAP: network_c BAA not yet signed.
    """
    ehr_config = EHR_SYSTEMS.get(network, {})
    return ehr_config.get("baa_signed", False)


# ── EHR endpoints ────────────────────────────────────────────

@router.get("/status/{network}", response_model=EHRConnectionStatus)
async def get_ehr_status(
    network: str,
    authorization: str = Header(None)
):
    """
    Check EHR integration status for a hospital network.
    Returns connection health and BAA compliance status.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    token = authorization.replace("Bearer ", "")
    validate_token(token)

    ehr_config = EHR_SYSTEMS.get(network)
    if not ehr_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown network: {network}"
        )

    return EHRConnectionStatus(
        network=network,
        vendor=ehr_config["vendor"],
        connected=True,
        baa_signed=ehr_config["baa_signed"]
    )


@router.get("/patient/{patient_id}", response_model=PatientSummary)
async def get_patient(
    request: Request,
    patient_id: str,
    authorization: str = Header(None)
):
    """
    Retrieve patient summary from EHR.
    Enforces network isolation — users can only see
    patients from their own hospital network.
    """
    # ── Authentication ───────────────────────────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    token = authorization.replace("Bearer ", "")
    user = validate_token(token)

    # ── Lookup patient ───────────────────────────────────────
    patient = get_patient_by_id(patient_id)
    if not patient:
        # Generic error — do not reveal whether patient exists
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # ── Network isolation check ──────────────────────────────
    if not check_network_access(user["network"], patient["hospital_network"]):
        log_security_event(
            "CROSS_NETWORK_ACCESS_ATTEMPT",
            user["user_id"],
            f"User from {user['network']} attempted to access "
            f"patient in {patient['hospital_network']}"
        )
        # Return same error as not found — do not leak patient exists
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # ── BAA compliance check ─────────────────────────────────
    if not check_baa_compliance(patient["hospital_network"]):
        log_security_event(
            "BAA_COMPLIANCE_VIOLATION",
            user["user_id"],
            f"PHI access attempted for network without signed BAA: "
            f"{patient['hospital_network']}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PHI access blocked — BAA not signed for this network"
        )

    # ── Audit log PHI access ─────────────────────────────────
    log_security_event(
        "PHI_ACCESS",
        user["user_id"],
        f"Patient: {patient_id} | Network: {patient['hospital_network']}"
    )

    studies = get_studies_for_patient(patient_id)

    return PatientSummary(
        patient_id=patient["patient_id"],
        hospital_network=patient["hospital_network"],
        conditions=patient["conditions"],
        active_studies=len(studies),
        last_visit=studies[-1]["date"] if studies else None
    )


@router.get("/patient/{patient_id}/studies",
            response_model=list[ImagingStudySummary])
async def get_patient_studies(
    request: Request,
    patient_id: str,
    authorization: str = Header(None)
):
    """
    Retrieve imaging studies for a patient.
    Used by DiagnosticAssist to load images for AI analysis.
    """
    # ── Authentication ───────────────────────────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    token = authorization.replace("Bearer ", "")
    user = validate_token(token)

    # ── Patient access validation ────────────────────────────
    patient = get_patient_by_id(patient_id)
    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    if not check_network_access(user["network"], patient["hospital_network"]):
        log_security_event(
            "CROSS_NETWORK_STUDIES_ACCESS",
            user["user_id"],
            f"Attempted cross-network study access: {patient_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # ── Audit log ────────────────────────────────────────────
    log_security_event(
        "IMAGING_STUDY_ACCESS",
        user["user_id"],
        f"Patient: {patient_id} | Studies requested"
    )

    studies = get_studies_for_patient(patient_id)
    return [
        ImagingStudySummary(
            study_id=s["study_id"],
            modality=s["modality"],
            date=s["date"],
            findings=s["findings"],
            ai_confidence=s["ai_confidence"]
        )
        for s in studies
    ]
