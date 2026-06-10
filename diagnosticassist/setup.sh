#!/bin/bash
# ─────────────────────────────────────────────────────────────
# DiagnosticAssist — Home Lab Setup Script (macOS)
# Run this once to set up your local audit target
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║     DiagnosticAssist — Home Lab Setup (macOS)        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Check Python version ──────────────────────────────────────
echo "→ Checking Python version..."
python3 --version
PYTHON_VERSION=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_VERSION" -lt 8 ]; then
    echo "✗ Python 3.8+ required"
    exit 1
fi
echo "✓ Python version OK"

# ── Create virtual environment ────────────────────────────────
echo ""
echo "→ Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# ── Activate virtual environment ──────────────────────────────
source venv/bin/activate
echo "✓ Virtual environment activated"

# ── Install dependencies ──────────────────────────────────────
echo ""
echo "→ Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Dependencies installed"

# ── Create __init__.py files ──────────────────────────────────
echo ""
echo "→ Creating package init files..."
touch config/__init__.py
touch endpoints/__init__.py
touch middleware/__init__.py
touch models/__init__.py
echo "✓ Package structure ready"

# ── Check if Ollama is available ──────────────────────────────
echo ""
echo "→ Checking Ollama availability..."
if command -v ollama &> /dev/null; then
    echo "✓ Ollama is installed"
    echo "  To enable LLM tests: ollama pull llama3.2"
else
    echo "⚠  Ollama not found — LLM tests will use mock responses"
    echo "  Install: brew install ollama"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Setup Complete!                         ║"
echo "║                                                      ║"
echo "║  Start the app:                                      ║"
echo "║    source venv/bin/activate                          ║"
echo "║    uvicorn app:app --reload --port 8000              ║"
echo "║                                                      ║"
echo "║  Open API docs:                                      ║"
echo "║    http://localhost:8000/docs                        ║"
echo "║                                                      ║"
echo "║  Run security tests (from audit directory):          ║"
echo "║    pytest tests/ -v                                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
