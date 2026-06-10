"""
DiagnosticAssist image analysis endpoint.
Analyzes X-rays, CT scans, and MRIs using deep learning.

SECURITY SURFACE:
- Adversarial image manipulation (FGSM, PGD attacks)
- DICOM metadata injection
- Out-of-distribution input detection
- Malformed image uploads
"""

import io
import json
import time
from pathlib import Path

import numpy as np
from fastapi import APIRouter, File, Header, HTTPException, Request, UploadFile, status
from pydantic import BaseModel

from config.settings import (
    ADVERSARIAL_CONFIDENCE_THRESHOLD,
    ALLOWED_IMAGE_FORMATS,
    MAX_IMAGE_SIZE_MB,
    MIN_IMAGE_DIMENSIONS,
    SUPPORTED_MODALITIES,
)
from middleware.auth import (
    log_security_event,
    rate_limit_check,
    validate_token,
)

router = APIRouter(prefix="/api/v1/imaging", tags=["Image Analysis"])
DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "mock_patients.json") as f:
    PATIENT_DATA = json.load(f)


# ── Response models ──────────────────────────────────────────

class DiagnosticResult(BaseModel):
    study_id: str
    modality: str
    findings: str
    confidence_score: float
    is_abnormal: bool
    adversarial_detected: bool
    ood_detected: bool
    processing_time_ms: float
    timestamp: float
    requires_radiologist_review: bool


class ValidationError(BaseModel):
    error: str
    detail: str


# ── Input validation ─────────────────────────────────────────

def validate_image_format(content_type: str, filename: str) -> bool:
    """Validate uploaded file is an allowed medical image format."""
    allowed_types = [
        "image/jpeg", "image/png",
        "application/dicom", "image/dicom"
    ]
    return content_type in allowed_types


def validate_image_size(file_size: int) -> bool:
    """Reject files exceeding the maximum allowed size."""
    max_bytes = MAX_IMAGE_SIZE_MB * 1024 * 1024
    return file_size <= max_bytes


def scan_dicom_metadata(metadata: dict) -> tuple[bool, list]:
    """
    Scan DICOM metadata for injection attempts.
    Malicious DICOM tags could reach the model as poisoned input.
    Returns (is_safe, suspicious_fields).
    """
    suspicious = []
    injection_patterns = [
        "<script", "javascript:", "<?php",
        "ignore previous", "system prompt",
        "../", "../../", "%2e%2e"
    ]

    for key, value in metadata.items():
        if isinstance(value, str):
            value_lower = value.lower()
            for pattern in injection_patterns:
                if pattern in value_lower:
                    suspicious.append(f"{key}: {pattern}")

    return len(suspicious) == 0, suspicious


def detect_adversarial_input(image_array: np.ndarray) -> tuple[bool, float]:
    """
    Basic adversarial input detection.
    Checks for statistical anomalies that indicate
    FGSM or PGD perturbations.

    Returns (is_adversarial, perturbation_score).
    """
    if image_array.dtype != np.float32:
        image_array = image_array.astype(np.float32) / 255.0

    # Check for unusual pixel value distributions
    # Adversarial examples often have abnormal high-frequency noise
    mean_val = np.mean(image_array)
    std_val = np.std(image_array)

    # Compute gradient magnitude as proxy for perturbation
    if len(image_array.shape) >= 2:
        grad_x = np.diff(image_array, axis=0)
        grad_y = np.diff(image_array, axis=1) if len(image_array.shape) > 1 else np.array([0])
        perturbation_score = float(np.mean(np.abs(grad_x)) + np.mean(np.abs(grad_y)))
    else:
        perturbation_score = 0.0

    # Flag if perturbation score exceeds threshold
    is_adversarial = perturbation_score > 0.15

    return is_adversarial, perturbation_score


def detect_out_of_distribution(image_array: np.ndarray) -> bool:
    """
    Detect out-of-distribution inputs.
    Images that are statistically far from training distribution
    should be flagged rather than silently misclassified.
    """
    if image_array.dtype != np.float32:
        image_array = image_array.astype(np.float32) / 255.0

    mean_val = float(np.mean(image_array))
    std_val = float(np.std(image_array))

    # Medical images have characteristic distributions
    # Very dark, very bright, or very uniform images are OOD
    is_ood = (
        mean_val < 0.05 or      # Nearly black
        mean_val > 0.95 or      # Nearly white
        std_val < 0.02          # Nearly uniform (no texture)
    )

    return is_ood


def mock_model_inference(
    image_array: np.ndarray,
    modality: str
) -> tuple[str, float, bool]:
    """
    Mock deep learning model inference.
    In production this would call the actual TensorFlow/PyTorch model.
    Returns (findings, confidence, is_abnormal).
    """
    # Simulate confidence based on image quality
    mean_val = float(np.mean(image_array))
    base_confidence = 0.85 + (mean_val * 0.1)
    confidence = min(0.99, max(0.50, base_confidence))

    # Mock findings based on modality
    findings_map = {
        "CHEST_XRAY": (
            "No acute cardiopulmonary process identified. "
            "Lungs are clear bilaterally.",
            False
        ),
        "CT_CHEST": (
            "No pulmonary embolism. No pneumothorax. "
            "Mild bilateral dependent atelectasis.",
            False
        ),
        "CARDIAC_MRI": (
            "Normal cardiac morphology and function. "
            "Ejection fraction within normal limits.",
            False
        ),
        "CT_ABDOMEN": (
            "No acute intraabdominal pathology identified.",
            False
        )
    }

    findings, is_abnormal = findings_map.get(
        modality,
        ("Analysis complete. Radiologist review recommended.", True)
    )

    return findings, confidence, is_abnormal


# ── Main imaging endpoint ────────────────────────────────────

@router.post("/analyze", response_model=DiagnosticResult)
async def analyze_image(
    request: Request,
    modality: str,
    patient_id: str,
    file: UploadFile = File(...),
    authorization: str = Header(None),
    dicom_metadata: str = None
):
    """
    Medical image analysis endpoint.
    Accepts DICOM, PNG, or JPEG medical images.
    Returns AI diagnostic suggestions with confidence scores.
    """
    start_time = time.time()

    # ── Authentication ───────────────────────────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    token = authorization.replace("Bearer ", "")
    user = validate_token(token)

    # ── Rate limiting ────────────────────────────────────────
    if not rate_limit_check(request.client.host):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

    # ── Modality validation ──────────────────────────────────
    if modality not in SUPPORTED_MODALITIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported modality. Allowed: {SUPPORTED_MODALITIES}"
        )

    # ── File format validation ───────────────────────────────
    if not validate_image_format(file.content_type, file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only DICOM, PNG, JPEG allowed."
        )

    # ── Read and size-check file ─────────────────────────────
    contents = await file.read()
    if not validate_image_size(len(contents)):
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {MAX_IMAGE_SIZE_MB}MB limit"
        )

    # ── DICOM metadata injection scan ───────────────────────
    if dicom_metadata:
        try:
            import json as json_lib
            metadata_dict = json_lib.loads(dicom_metadata)
            is_safe, suspicious = scan_dicom_metadata(metadata_dict)
            if not is_safe:
                log_security_event(
                    "DICOM_INJECTION_ATTEMPT",
                    user["user_id"],
                    f"Suspicious fields: {suspicious}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid DICOM metadata detected"
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malformed DICOM metadata"
            )

    # ── Convert to numpy array for analysis ─────────────────
    try:
        image_array = np.frombuffer(contents, dtype=np.uint8)
        if len(image_array) < 64:
            raise ValueError("Image too small")
        image_array = image_array.astype(np.float32)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not process image data"
        )

    # ── Adversarial detection ────────────────────────────────
    adversarial_detected, perturbation_score = detect_adversarial_input(
        image_array
    )
    if adversarial_detected:
        log_security_event(
            "ADVERSARIAL_INPUT_DETECTED",
            user["user_id"],
            f"Perturbation score: {perturbation_score:.4f}"
        )

    # ── OOD detection ────────────────────────────────────────
    ood_detected = detect_out_of_distribution(image_array)
    if ood_detected:
        log_security_event(
            "OOD_INPUT_DETECTED",
            user["user_id"],
            f"Patient: {patient_id} | Modality: {modality}"
        )

    # ── Model inference ──────────────────────────────────────
    findings, confidence, is_abnormal = mock_model_inference(
        image_array, modality
    )

    # Reduce confidence if adversarial or OOD detected
    if adversarial_detected or ood_detected:
        confidence = min(confidence, ADVERSARIAL_CONFIDENCE_THRESHOLD)

    # ── Audit log ────────────────────────────────────────────
    processing_time = (time.time() - start_time) * 1000
    log_security_event(
        "IMAGE_ANALYSIS",
        user["user_id"],
        f"Patient: {patient_id} | Modality: {modality} | "
        f"Confidence: {confidence:.2f} | Adversarial: {adversarial_detected}"
    )

    return DiagnosticResult(
        study_id=f"IMG-{int(time.time())}",
        modality=modality,
        findings=findings,
        confidence_score=round(confidence, 3),
        is_abnormal=is_abnormal,
        adversarial_detected=adversarial_detected,
        ood_detected=ood_detected,
        processing_time_ms=round(processing_time, 2),
        timestamp=time.time(),
        requires_radiologist_review=(
            adversarial_detected or ood_detected or confidence < 0.7
        )
    )
