"""
DiagnosticAssist — Mock Healthcare AI Platform
Target application for the HealthTech AI Security Audit.

This is a realistic simulation of the DiagnosticAssist platform
described in the Coursera AI Security capstone project.

Run locally:
    uvicorn app:app --reload --port 8000

API docs:
    http://localhost:8000/docs
    http://localhost:8000/redoc
"""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import APP_NAME, APP_VERSION, DEBUG
from endpoints.auth import router as auth_router
from endpoints.ehr_integration import router as ehr_router
from endpoints.image_analysis import router as imaging_router
from endpoints.llm_interface import router as llm_router


# ── App lifespan ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"""
╔══════════════════════════════════════════════════════════╗
║          DiagnosticAssist — Security Audit Target        ║
║                                                          ║
║  API Docs:    http://localhost:8000/docs                  ║
║  Health:      http://localhost:8000/health               ║
║  Auth:        http://localhost:8000/api/v1/auth          ║
║  LLM:         http://localhost:8000/api/v1/llm           ║
║  Imaging:     http://localhost:8000/api/v1/imaging       ║
║  EHR:         http://localhost:8000/api/v1/ehr           ║
║                                                          ║
║  ⚠  FOR SECURITY TESTING ONLY — NOT FOR PRODUCTION  ⚠   ║
╚══════════════════════════════════════════════════════════╝
    """)
    yield
    print("DiagnosticAssist shutting down...")


# ── FastAPI app ──────────────────────────────────────────────

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="""
## DiagnosticAssist Security Audit Target

Mock implementation of the HealthTech AI DiagnosticAssist platform.
Used as the target application for the comprehensive AI security audit.

### Security surfaces covered:
- **LLM Interface** — Prompt injection, PHI leakage, model extraction
- **Image Analysis** — Adversarial inputs (FGSM/PGD), DICOM injection, OOD detection
- **EHR Integration** — Cross-network access, PHI boundary, BAA compliance
- **Authentication** — Brute force, MFA bypass, token enumeration

### Known security gaps (intentional for audit):
- GAP-001: api_client role bypasses MFA
- GAP-002: Token expiry not enforced in dev mode
- GAP-003: Login error reveals whether username exists
- GAP-004: network_c BAA not signed
    """,
    lifespan=lifespan,
    debug=DEBUG
)


# ── Middleware ───────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # Remove server info
    response.headers["server"] = ""
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests for audit trail."""
    start = time.time()
    response = await call_next(request)
    duration = (time.time() - start) * 1000
    print(
        f"[REQUEST] {request.method} {request.url.path} "
        f"→ {response.status_code} ({duration:.1f}ms)"
    )
    return response


# ── Routers ──────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(llm_router)
app.include_router(imaging_router)
app.include_router(ehr_router)


# ── Core endpoints ───────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint — used by CI/CD and monitoring."""
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION,
        "timestamp": time.time()
    }


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/health",
        "note": "Security audit target — for testing only"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler.
    Never expose internal errors or stack traces to clients.
    """
    print(f"[ERROR] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred"}
        # NOTE: No stack trace, no exception message exposed
    )


# ── Prometheus metrics endpoint ──────────────────────────────
from prometheus_client import make_wsgi_app, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint — scraped every 15s by Prometheus."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
