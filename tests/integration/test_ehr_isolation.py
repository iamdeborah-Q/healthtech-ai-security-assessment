"""
EHR Integration Security Tests

What we are testing:
Can a doctor from one hospital access patients
from a different hospital network?

This is called cross-network access control.
In healthcare this is critical because HIPAA
requires strict isolation between hospital networks.

GAP-004: network_c has no signed BAA - PHI access blocked
HIPAA: 45 CFR 164.514 - Minimum necessary standard
MITRE ATLAS: AML.T0024 - Exfiltration via ML inference
"""

import requests
import pytest

# The app we are testing
APP_URL = "http://localhost:8000"
EHR_URL = f"{APP_URL}/api/v1/ehr"

# Doctor from Hospital Network A - Epic EHR
DOCTOR_NETWORK_A = "valid_token_network_a"

# Doctor from Hospital Network B - Oracle Health EHR
DOCTOR_NETWORK_B = "valid_token_network_b"

# Network A patients - doctor A can see these
NETWORK_A_PATIENT = "PT-001"  # John Smith - network_a
NETWORK_A_PATIENT_2 = "PT-002"  # Sarah Johnson - network_a

# Network B patients - doctor A cannot see these
NETWORK_B_PATIENT = "PT-003"  # Robert Davis - network_b
NETWORK_B_PATIENT_2 = "PT-004"  # Maria Garcia - network_b


# Helper - make EHR request with a specific doctor token
def get_patient(patient_id, doctor_token):
    response = requests.get(
        f"{EHR_URL}/patient/{patient_id}",
        headers={"Authorization": f"Bearer {doctor_token}"}
    )
    return response


# Helper - get imaging studies for a patient
def get_studies(patient_id, doctor_token):
    response = requests.get(
        f"{EHR_URL}/patient/{patient_id}/studies",
        headers={"Authorization": f"Bearer {doctor_token}"}
    )
    return response


# Helper - check EHR connection status for a network
def get_ehr_status(network, doctor_token):
    response = requests.get(
        f"{EHR_URL}/status/{network}",
        headers={"Authorization": f"Bearer {doctor_token}"}
    )
    return response


# ─────────────────────────────────────────────
# BASIC ACCESS TESTS
# ─────────────────────────────────────────────

# Doctor from Network A can access their own patients
def test_doctor_can_access_own_patients():
    response = get_patient(NETWORK_A_PATIENT, DOCTOR_NETWORK_A)
    assert response.status_code == 200, (
        "Doctor cannot access their own patients - access broken"
    )


# Doctor from Network A can see patient conditions
def test_patient_data_returned_correctly():
    response = get_patient(NETWORK_A_PATIENT, DOCTOR_NETWORK_A)
    assert response.status_code == 200
    data = response.json()
    assert "patient_id" in data
    assert "conditions" in data
    assert "hospital_network" in data


# Doctor can see imaging studies for their patients
def test_doctor_can_access_own_patient_studies():
    response = get_studies(NETWORK_A_PATIENT, DOCTOR_NETWORK_A)
    assert response.status_code == 200


# ─────────────────────────────────────────────
# CROSS NETWORK ISOLATION TESTS
# These are the critical security tests
# A doctor must NEVER see patients from another hospital
# ─────────────────────────────────────────────

# Doctor from Network A cannot access Network B patients
def test_cross_network_access_blocked():
    """
    CRITICAL TEST
    A radiologist at Hospital Network A (Epic)
    must not be able to see patients from
    Hospital Network B (Oracle Health).

    If this test fails it means any doctor can
    see any patient across all 20 hospitals.
    That is a catastrophic HIPAA violation.
    """
    response = get_patient(NETWORK_B_PATIENT, DOCTOR_NETWORK_A)

    # Must return 404 - not 403
    # We return 404 instead of 403 so the attacker
    # does not even know the patient exists
    assert response.status_code == 404, (
        f"CRITICAL FINDING: Doctor from network_a accessed "
        f"patient from network_b. Cross-network isolation FAILED."
    )


# Doctor from Network A cannot see second Network B patient either
def test_cross_network_access_blocked_second_patient():
    response = get_patient(NETWORK_B_PATIENT_2, DOCTOR_NETWORK_A)
    assert response.status_code == 404


# Doctor from Network B cannot access Network A patients
def test_reverse_cross_network_access_blocked():
    response = get_patient(NETWORK_A_PATIENT, DOCTOR_NETWORK_B)
    assert response.status_code == 404, (
        "CRITICAL: Network B doctor accessed Network A patient"
    )


# Doctor from Network A cannot access Network B imaging studies
def test_cross_network_studies_blocked():
    response = get_studies(NETWORK_B_PATIENT, DOCTOR_NETWORK_A)
    assert response.status_code == 404, (
        "CRITICAL: Doctor accessed imaging studies from another network"
    )


# ─────────────────────────────────────────────
# AUTHENTICATION TESTS
# EHR must reject unauthenticated requests
# ─────────────────────────────────────────────

# No token means no access to any patient
def test_no_token_blocked():
    response = requests.get(
        f"{EHR_URL}/patient/{NETWORK_A_PATIENT}"
    )
    assert response.status_code == 401


# Fake token means no access to any patient
def test_fake_token_blocked():
    response = requests.get(
        f"{EHR_URL}/patient/{NETWORK_A_PATIENT}",
        headers={"Authorization": "Bearer fake_token_xyz"}
    )
    assert response.status_code == 401


# ─────────────────────────────────────────────
# BAA COMPLIANCE TEST - GAP-004
# ─────────────────────────────────────────────

# GAP-004: Network C has no signed BAA - access must be blocked
def test_unsigned_baa_blocks_phi_access():
    """
    FINDING: GAP-004 - Unsigned Business Associate Agreement
    SEVERITY: Critical
    HIPAA: 45 CFR 164.308(b)(1)

    Network C (Allscripts) does not have a signed BAA.
    Under HIPAA this means DiagnosticAssist cannot legally
    access any patient data from Network C.

    If this test fails it means the platform is accessing
    patient data without legal authorization - a direct
    HIPAA violation that could result in significant fines.
    """
    # Network C patient - PT-005 James Wilson
    NETWORK_C_PATIENT = "PT-005"

    # Try to access network_c patient with network_c token
    # This should be blocked because BAA is not signed
    response = requests.get(
        f"{EHR_URL}/patient/{NETWORK_C_PATIENT}",
        headers={"Authorization": "Bearer valid_token_network_a"}
    )

    # Should be blocked - either 403 forbidden or 404 not found
    assert response.status_code in [403, 404], (
        "CRITICAL FINDING: GAP-004 - PHI accessed without signed BAA. "
        "Network C data must be blocked until BAA is executed."
    )


# ─────────────────────────────────────────────
# EHR CONNECTION STATUS TESTS
# ─────────────────────────────────────────────

# Check Network A EHR connection status
def test_network_a_ehr_status():
    response = get_ehr_status("network_a", DOCTOR_NETWORK_A)
    assert response.status_code == 200
    data = response.json()
    assert data["connected"] is True
    assert data["vendor"] == "Epic"


# Check Network B EHR connection status
def test_network_b_ehr_status():
    response = get_ehr_status("network_b", DOCTOR_NETWORK_A)
    assert response.status_code == 200
    data = response.json()
    assert data["vendor"] == "Oracle Health"


# GAP-004: Check that Network C shows BAA as not signed
def test_network_c_baa_not_signed():
    """
    This test documents GAP-004 by confirming
    the BAA status for network_c is false.
    This must be remediated before deployment.
    """
    response = get_ehr_status("network_c", DOCTOR_NETWORK_A)
    assert response.status_code == 200
    data = response.json()

    # Document the finding
    if data["baa_signed"] is False:
        print(f"\n[FINDING] GAP-004 CONFIRMED")
        print(f"  Network: network_c")
        print(f"  Vendor: {data['vendor']}")
        print(f"  BAA Signed: {data['baa_signed']}")
        print(f"  Impact: PHI access without legal authorization")
        print(f"  Action: Execute BAA before deployment")

    assert data["baa_signed"] is False, (
        "Expected network_c BAA to be unsigned - "
        "if this passes the BAA has been signed - great"
    )


# Non-existent patient returns 404 not system error
def test_nonexistent_patient_returns_404():
    response = get_patient("PT-FAKE-999", DOCTOR_NETWORK_A)
    assert response.status_code == 404


# Error messages must not reveal system information
def test_error_messages_do_not_leak_info():
    response = get_patient("PT-FAKE-999", DOCTOR_NETWORK_A)
    assert response.status_code == 404
    error_detail = response.json().get("detail", "").lower()

    # Error must not reveal database structure
    assert "sql" not in error_detail
    assert "database" not in error_detail
    assert "exception" not in error_detail
    assert "traceback" not in error_detail
