#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Cyber Detection Module - importable wrapper
Keeps all original logic from cyber_detector.py intact
"""

import hashlib
import json
import os
import fitz
from datetime import datetime


HASH_STORE_FILE = os.path.join(os.path.dirname(__file__), 'hash_store.json')


# ──────────────────────────────────────────────────────────────
# Hash utilities
# ──────────────────────────────────────────────────────────────

def generate_hash(pdf_path):
    with open(pdf_path, "rb") as f:
        file_bytes = f.read()
    return hashlib.sha256(file_bytes).hexdigest()


def store_hash(pdf_path, hash_value):
    if os.path.exists(HASH_STORE_FILE):
        with open(HASH_STORE_FILE, "r") as f:
            store = json.load(f)
    else:
        store = {}

    store[pdf_path] = {
        "hash": hash_value,
        "timestamp": datetime.now().isoformat()
    }

    with open(HASH_STORE_FILE, "w") as f:
        json.dump(store, f, indent=4)


# ──────────────────────────────────────────────────────────────
# Check 1: Resubmission / duplicate detection
# ──────────────────────────────────────────────────────────────

def check_resubmission(pdf_path):
    flags = []
    new_hash = generate_hash(pdf_path)

    if not os.path.exists(HASH_STORE_FILE):
        store_hash(pdf_path, new_hash)
        return flags, new_hash

    with open(HASH_STORE_FILE, "r") as f:
        store = json.load(f)

    if pdf_path in store:
        stored_hash = store[pdf_path]["hash"]
        stored_time = store[pdf_path]["timestamp"]
        if stored_hash != new_hash:
            flags.append({
                "type": "resubmission_detected",
                "description": f"Document was previously submitted on {stored_time} but content has changed — possible tampering",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
    else:
        for stored_path, stored_data in store.items():
            if stored_data["hash"] == new_hash and stored_path != pdf_path:
                flags.append({
                    "type": "duplicate_document",
                    "description": f"Document is identical to previously submitted file: {os.path.basename(stored_path)}",
                    "severity": "HIGH",
                    "confidence": 0.99
                })
                break
        store_hash(pdf_path, new_hash)

    return flags, new_hash


# ──────────────────────────────────────────────────────────────
# Check 2: Metadata anomalies
# ──────────────────────────────────────────────────────────────

def check_metadata(pdf_path):
    flags = []
    metadata_info = {}

    legitimate_software = [
        "tally", "sap", "finacle", "bankmaster", "temenos",
        "microsoft word", "libreoffice", "adobe acrobat",
        "fpdf", "reportlab", "itext", "pdfkit"
    ]

    doc = fitz.open(pdf_path)
    metadata = doc.metadata
    doc.close()

    metadata_info = {
        "title": metadata.get("title", ""),
        "author": metadata.get("author", ""),
        "creator": metadata.get("creator", ""),
        "producer": metadata.get("producer", ""),
        "creation_date": metadata.get("creationDate", ""),
        "modification_date": metadata.get("modDate", ""),
    }

    # Author missing
    author = metadata.get("author", "").strip()
    if not author:
        flags.append({
            "type": "author_missing",
            "description": "Document has no author metadata — legitimate documents always carry author information",
            "severity": "MEDIUM",
            "confidence": 0.70
        })

    # Rapid modification
    creation_date = metadata.get("creationDate", "")
    mod_date = metadata.get("modDate", "")
    if creation_date and mod_date:
        try:
            def parse_pdf_date(date_str):
                date_str = date_str.replace("D:", "").strip()[:14]
                return datetime.strptime(date_str, "%Y%m%d%H%M%S")

            created = parse_pdf_date(creation_date)
            modified = parse_pdf_date(mod_date)
            diff_minutes = (modified - created).total_seconds() / 60

            if 0 < diff_minutes < 60:
                flags.append({
                    "type": "rapid_modification",
                    "description": f"Document was modified {diff_minutes:.0f} minutes after creation — suspicious editing pattern",
                    "severity": "HIGH",
                    "confidence": 0.80
                })
        except Exception:
            pass

    # Suspicious creator/producer
    creator = metadata.get("creator", "").lower()
    producer = metadata.get("producer", "").lower()
    suspicious_tools = ["photoshop", "gimp", "inkscape", "canva", "illustrator", "paint"]

    for tool in suspicious_tools:
        if tool in creator or tool in producer:
            flags.append({
                "type": "suspicious_creator_tool",
                "description": f"Document created with image editing software ({tool}) — not typical for financial documents",
                "severity": "HIGH",
                "confidence": 0.85
            })
            break

    return flags, metadata_info


# ──────────────────────────────────────────────────────────────
# Check 3: File anomalies
# ──────────────────────────────────────────────────────────────

def check_file_anomalies(pdf_path, doc_type="unknown"):
    flags = []

    min_pages = {
        "salary_slip": 1,
        "form_16": 2,
        "bank_statement": 2,
        "itr": 3,
        "property_valuation": 2,
        "unknown": 1
    }

    doc = fitz.open(pdf_path)

    # Encryption
    if doc.is_encrypted:
        flags.append({
            "type": "pdf_encrypted",
            "description": "Document is encrypted or password protected — suspicious for a loan document",
            "severity": "HIGH",
            "confidence": 0.85
        })

    # Embedded JavaScript
    try:
        js_found = False
        for i in range(len(doc)):
            page = doc[i]
            if "/JS" in str(page.get_text("rawdict")):
                js_found = True
                break
        if js_found:
            flags.append({
                "type": "embedded_javascript",
                "description": "Document contains embedded JavaScript — sign of a potentially malicious file",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
    except Exception:
        pass

    # Embedded attachments
    try:
        attachments = doc.embfile_count()
        if attachments > 0:
            flags.append({
                "type": "embedded_attachments",
                "description": f"Document contains {attachments} embedded attachment(s) — suspicious for a financial document",
                "severity": "HIGH",
                "confidence": 0.80
            })
    except Exception:
        pass

    # Page count
    page_count = doc.page_count
    expected_min = min_pages.get(doc_type, 1)
    if page_count < expected_min:
        flags.append({
            "type": "suspicious_page_count",
            "description": f"Document has only {page_count} page(s) — expected at least {expected_min} for {doc_type}",
            "severity": "MEDIUM",
            "confidence": 0.75
        })

    # File size
    file_size_kb = os.path.getsize(pdf_path) / 1024
    if file_size_kb < 5:
        flags.append({
            "type": "suspicious_file_size",
            "description": f"Document file size is only {file_size_kb:.1f} KB — suspiciously small",
            "severity": "MEDIUM",
            "confidence": 0.70
        })

    doc.close()
    return flags


# ──────────────────────────────────────────────────────────────
# Check 4: Scanned document / resolution
# ──────────────────────────────────────────────────────────────

def check_scanned_document(pdf_path):
    flags = []

    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    scanned_pages = 0
    resolutions = []

    for page_num in range(total_pages):
        page = doc[page_num]
        text = page.get_text().strip()

        if len(text) < 50:
            scanned_pages += 1
            try:
                mat = fitz.Matrix(1, 1)
                pix = page.get_pixmap(matrix=mat)
                width = pix.width
                height = pix.height
                estimated_dpi = min(width, height) / 8.27
                resolutions.append(estimated_dpi)

                if estimated_dpi < 150:
                    flags.append({
                        "type": "low_resolution_scan",
                        "description": f"Page {page_num+1} has low resolution ({estimated_dpi:.0f} DPI estimated) — may indicate re-scanned forgery",
                        "severity": "HIGH",
                        "confidence": 0.80
                    })
            except Exception:
                pass

    if scanned_pages == total_pages:
        flags.append({
            "type": "fully_scanned_document",
            "description": f"All {total_pages} page(s) appear image-based — higher fraud risk than native PDF",
            "severity": "MEDIUM",
            "confidence": 0.65
        })
    elif scanned_pages > 0:
        flags.append({
            "type": "mixed_document",
            "description": f"{scanned_pages} of {total_pages} pages appear scanned — inconsistent document structure",
            "severity": "MEDIUM",
            "confidence": 0.70
        })

    if len(resolutions) > 1:
        max_res = max(resolutions)
        min_res = min(resolutions)
        if (max_res - min_res) > 100:
            flags.append({
                "type": "inconsistent_resolution",
                "description": f"Resolution varies across pages ({min_res:.0f} to {max_res:.0f} DPI) — possible spliced pages",
                "severity": "HIGH",
                "confidence": 0.85
            })

    doc.close()
    return flags


# ──────────────────────────────────────────────────────────────
# Master cyber analysis
# ──────────────────────────────────────────────────────────────

def run_cyber_analysis(pdf_path, doc_type="unknown"):
    all_flags = []
    steps = []

    # Step 1: Hashing & resubmission
    try:
        resubmission_flags, doc_hash = check_resubmission(pdf_path)
        all_flags.extend(resubmission_flags)
        steps.append({"step": "Hash & Resubmission", "status": "ok", "flags": len(resubmission_flags)})
    except Exception as e:
        doc_hash = "error"
        steps.append({"step": "Hash & Resubmission", "status": "error", "message": str(e)})

    # Step 2: Metadata
    try:
        metadata_flags, metadata_info = check_metadata(pdf_path)
        all_flags.extend(metadata_flags)
        steps.append({"step": "Metadata Analysis", "status": "ok", "flags": len(metadata_flags)})
    except Exception as e:
        metadata_info = {}
        steps.append({"step": "Metadata Analysis", "status": "error", "message": str(e)})

    # Step 3: File anomalies
    try:
        file_flags = check_file_anomalies(pdf_path, doc_type)
        all_flags.extend(file_flags)
        steps.append({"step": "File Anomalies", "status": "ok", "flags": len(file_flags)})
    except Exception as e:
        steps.append({"step": "File Anomalies", "status": "error", "message": str(e)})

    # Step 4: Scan detection
    try:
        scan_flags = check_scanned_document(pdf_path)
        all_flags.extend(scan_flags)
        steps.append({"step": "Scan Detection", "status": "ok", "flags": len(scan_flags)})
    except Exception as e:
        steps.append({"step": "Scan Detection", "status": "error", "message": str(e)})

    # Score
    if not all_flags:
        cyber_score = 0.0
        risk_level = "LOW"
    else:
        severity_weights = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}
        total_weight = sum(
            severity_weights.get(f["severity"], 0.5) * f["confidence"]
            for f in all_flags
        )
        cyber_score = min(round(total_weight / (len(all_flags) + 1), 2), 1.0)

        if cyber_score >= 0.65:
            risk_level = "HIGH"
        elif cyber_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

    return {
        "document_hash": doc_hash,
        "cyber_score": cyber_score,
        "risk_level": risk_level,
        "flags": all_flags,
        "metadata": metadata_info,
        "steps": steps,
        "summary": {
            "total": len(all_flags),
            "critical": len([f for f in all_flags if f["severity"] == "CRITICAL"]),
            "high": len([f for f in all_flags if f["severity"] == "HIGH"]),
            "medium": len([f for f in all_flags if f["severity"] == "MEDIUM"]),
            "low": len([f for f in all_flags if f["severity"] == "LOW"]),
        }
    }
