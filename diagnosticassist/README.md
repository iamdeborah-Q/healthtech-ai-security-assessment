# DiagnosticAssist — Mock Target Application

> ⚠️ **For security testing only. Never deploy to production.**

This is the mock implementation of the DiagnosticAssist healthcare AI platform used as the audit target for the HealthTech AI Security Audit project.

---

## What this application simulates

DiagnosticAssist is a fictional AI-powered medical diagnostic platform that:
- Analyzes medical images (X-rays, CT scans, MRIs) using deep learning
- Provides an LLM-powered natural language interface for radiologists
- Integrates with hospital EHR systems across 5 hospital networks
- Serves 500,000+ patients annually

---

## Quick start (macOS)

```bash
# 1. Run setup
chmod +x setup.sh && ./setup.sh

# 2. Activate environment
source venv/bin/activate

# 3. Start the application
uvicorn app:app --reload --port 8000

# 4. Open API docs
open http://localhost:8000/docs
```

---

## API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/api/v1/auth/login` | POST | Authenticate user |
| `/api/v1/auth/mfa/verify` | POST | Verify MFA code |
| `/api/v1/llm/query` | POST | Query LLM interface |
| `/api/v1/imaging/analyze` | POST | Analyze medical image |
| `/api/v1/ehr/patient/{id}` | GET | Get patient from EHR |
| `/api/v1/ehr/patient/{id}/studies` | GET | Get imaging studies |
| `/api/v1/ehr/status/{network}` | GET | EHR connection status |

---

## Test tokens

Use these tokens in the `Authorization: Bearer <token>` header:

| Token | Role | Network |
|---|---|---|
| `valid_token_network_a` | radiologist | network_a (Epic) |
| `valid_token_network_b` | radiologist | network_b (Oracle Health) |
| `admin_token_network_a` | hospital_admin | network_a |

---

## Known security gaps (intentional for audit)

| Gap ID | Description | Endpoint |
|---|---|---|
| GAP-001 | api_client role bypasses MFA | `/auth/login` |
| GAP-002 | Token expiry not enforced in dev | All authenticated |
| GAP-003 | Login error reveals username existence | `/auth/login` |
| GAP-004 | network_c BAA not signed | `/ehr/*` |

These gaps are intentional — your security tests should detect all of them.
