#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Fraud Detector Module - importable wrapper
Delegates to document_fraud_detector_enhanced.py keeping all logic intact
"""

import os
import sys
import json
from datetime import datetime

# Make sure the fraud detector can be imported from same directory
sys.path.insert(0, os.path.dirname(__file__))


def run_fraud_analysis(pdf_path, output_folder):
    """
    Run the full document fraud detection pipeline.
    Returns structured JSON-serializable result.
    """
    from document_fraud_detector_enhanced import analyze_document

    # analyze_document outputs an annotated PDF to pdf_path.replace(".pdf","_flagged.pdf")
    result = analyze_document(pdf_path)

    # Move annotated PDF to output folder if it exists
    annotated_pdf = result.get("annotated_pdf", "")
    annotated_filename = None

    if annotated_pdf and os.path.exists(annotated_pdf):
        base = os.path.basename(annotated_pdf)
        dest = os.path.join(output_folder, base)
        if annotated_pdf != dest:
            import shutil
            shutil.move(annotated_pdf, dest)
        annotated_filename = base

    # Build clean response
    flags = result.get("flags", [])
    risk_level = result.get("risk_level", "UNKNOWN")
    risk_score = result.get("risk_score", 0)
    credibility = result.get("credibility_score", 0)

    financial = result.get("financial_data", {})
    # Convert any non-serializable values
    clean_financial = {}
    for k, v in financial.items():
        try:
            json.dumps(v)
            clean_financial[k] = v
        except Exception:
            clean_financial[k] = str(v)

    return {
        "document_type": result.get("document_type", "unknown"),
        "risk_level": risk_level,
        "risk_score": round(risk_score, 3),
        "credibility_score": round(credibility, 1),
        "flags": flags,
        "verified_companies": result.get("verified_companies", []),
        "financial_data": clean_financial,
        "annotated_pdf": annotated_filename,
        "metadata": result.get("metadata", {}),
        "summary": {
            "total": len(flags),
            "critical": len([f for f in flags if f.get("severity") == "CRITICAL"]),
            "high":     len([f for f in flags if f.get("severity") == "HIGH"]),
            "medium":   len([f for f in flags if f.get("severity") == "MEDIUM"]),
            "low":      len([f for f in flags if f.get("severity") == "LOW"]),
        }
    }