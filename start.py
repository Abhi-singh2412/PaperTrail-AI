#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DOCSHIELD — Document Fraud Detection System
Entry point. Run this file to launch the web server.

Usage:
    python start.py

Then open: http://localhost:5000
"""

import os
import sys

# ── Dependency check ──────────────────────────────────────────
REQUIRED = {
    "fitz":     "pymupdf",
    "spacy":    "spacy",
    "dateutil": "python-dateutil",
    "flask":    "flask",
    "flask_cors": "flask-cors",
}

missing = []
for module, package in REQUIRED.items():
    try:
        __import__(module)
    except ImportError:
        missing.append(package)

if missing:
    print("\n❌ Missing dependencies:")
    for pkg in missing:
        print(f"   • {pkg}")
    print("\nInstall with:")
    print("   pip install " + " ".join(missing))
    if "spacy" not in missing:
        print("\nAlso run:")
        print("   python -m spacy download en_core_web_sm")
    sys.exit(1)

# Check spaCy model
try:
    import spacy
    spacy.load("en_core_web_sm")
except OSError:
    print("\n⚠️  spaCy model not found. Downloading...")
    os.system(f"{sys.executable} -m spacy download en_core_web_sm")

# ── Launch server ─────────────────────────────────────────────
print("\n" + "="*60)
print("  DocShield — Document Fraud Detection System")
print("  Open: http://localhost:5000")
print("="*60 + "\n")

# Change to app directory so relative imports work
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from app import app
app.run(debug=False, port=5000, host='0.0.0.0')