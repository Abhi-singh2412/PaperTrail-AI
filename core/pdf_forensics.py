"""
core/pdf_forensics.py
─────────────────────
PDF metadata extraction and forensic flag detection.
Handles: .pdf files

Tools used:
  - pdfinfo  (system binary from poppler-utils)
  - pypdf    (Python library)
  - raw binary scan for stream-level anomalies
"""

import os
import subprocess
from datetime import datetime

from .utils import sha256_hash, safe_str, parse_pdf_date


# ---
# MAIN EXTRACTOR
# ---

def extract_pdf_metadata(filepath: str) -> dict:
    """
    Extract all forensically significant metadata from a PDF file.

    Returns a dict with keys:
        file_type, source_file, sha256, file_size_bytes,
        pdfinfo, internal_xmp, stream_objects, forensic_flags
    """
    result = {
        "file_type": "PDF",
        "source_file": os.path.basename(filepath),
        "sha256": sha256_hash(filepath),
        "file_size_bytes": os.path.getsize(filepath),
        "pdfinfo": {},
        "internal_xmp": {},
        "stream_objects": {},
        "forensic_flags": []
    }

    _run_pdfinfo(filepath, result)
    _run_pypdf(filepath, result)
    _scan_binary_streams(filepath, result)
    _apply_forensic_flags(result)

    return result


# ---
# STEP 1 — pdfinfo (system tool, very fast, reliable)
# ---

def _run_pdfinfo(filepath: str, result: dict):
    """
    Use the pdfinfo command-line tool (from poppler-utils) to extract
    basic PDF properties: title, author, page count, PDF version, etc.

    Install:  sudo apt install poppler-utils
    """
    try:
        out = subprocess.check_output(
            ["pdfinfo", filepath], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                result["pdfinfo"][key.strip()] = val.strip()
    except FileNotFoundError:
        result["pdfinfo"]["error"] = "pdfinfo not installed (run: sudo apt install poppler-utils)"
    except Exception as e:
        result["pdfinfo"]["error"] = str(e)


# ---
# STEP 2 — pypdf (deep metadata + XMP stream)
# ---

def _run_pypdf(filepath: str, result: dict):
    """
    Use pypdf to read the PDF metadata dictionary (XMP/DocInfo).
    Extracts: title, author, creator app, producer app, dates, encryption status.

    Key forensic insight:
        creator  = the app that CREATED the original document (e.g. Microsoft Word)
        producer = the app that CONVERTED it to PDF (e.g. ilovepdf — a red flag)
    """
    try:
        from pypdf import PdfReader
        reader = PdfReader(filepath)
        meta = reader.metadata or {}

        fields = {
            "title":        meta.get("/Title"),
            "author":       meta.get("/Author"),
            "subject":      meta.get("/Subject"),
            "creator":      meta.get("/Creator"),      # app that made the source doc
            "producer":     meta.get("/Producer"),     # PDF renderer / converter
            "created":      meta.get("/CreationDate"),
            "modified":     meta.get("/ModDate"),
            "keywords":     meta.get("/Keywords"),
            "trapped":      meta.get("/Trapped"),
        }

        # Parse raw PDF date strings (D:YYYYMMDDHHmmSS) into ISO format
        fields["created_iso"]  = parse_pdf_date(safe_str(fields["created"]))
        fields["modified_iso"] = parse_pdf_date(safe_str(fields["modified"]))

        result["internal_xmp"] = {k: safe_str(v) for k, v in fields.items()}
        result["internal_xmp"]["page_count"]   = len(reader.pages)
        result["internal_xmp"]["is_encrypted"] = reader.is_encrypted

        # Check XMP stream for additional metadata
        try:
            xmp = reader.xmp_metadata
            if xmp:
                result["internal_xmp"]["xmp_present"]   = True
                result["internal_xmp"]["xmp_dc_format"] = safe_str(
                    getattr(xmp, "dc_format", None)
                )
        except Exception:
            result["internal_xmp"]["xmp_present"] = False

    except ImportError:
        result["internal_xmp"]["error"] = "pypdf not installed (run: pip install pypdf)"
    except Exception as e:
        result["internal_xmp"]["error"] = str(e)


# ---
# STEP 3 — Raw binary stream scan
# ---

def _scan_binary_streams(filepath: str, result: dict):
    """
    Read the raw bytes of the PDF and look for suspicious stream markers.

    What we look for:
        /JavaScript  — hidden JS code (not normal in loan documents)
        /EmbeddedFile — hidden files embedded inside the PDF
        /Launch      — actions that can open external programs
        %%EOF        — each extra EOF means the doc was saved incrementally
                       (i.e. someone kept opening and editing it)
        editing tool names — Foxit, Smallpdf, ilovepdf, etc.
        scanner names — ScanSnap, EPSON, Canon (confirms physical scan origin)
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # Known PDF editing tools (suspicious in "original" bank documents)
        editing_tools = [
            b"Adobe Acrobat", b"Foxit", b"LibreOffice",
            b"PDFescape", b"Smallpdf", b"ilovepdf",
            b"pdf24", b"PDFill", b"Nitro"
        ]
        # Scanner brand signatures (confirms physical scan origin — a good sign)
        scanner_hints = [b"ScanSnap", b"EPSON", b"Canon", b"HP Scan", b"Xerox", b"KONICA"]

        result["stream_objects"] = {
            "javascript_streams":       raw.count(b"/JavaScript") + raw.count(b"/JS"),
            "embedded_files":           raw.count(b"/EmbeddedFile"),
            "launch_actions":           raw.count(b"/Launch"),
            "scanner_origin_detected":  any(hint in raw for hint in scanner_hints),
            "editing_tools_detected":   [t.decode() for t in editing_tools if t in raw],
            # Each extra %%EOF beyond the first = one incremental save (re-edit session)
            "incremental_saves_count":  max(0, raw.count(b"%%EOF") - 1),
        }
    except Exception as e:
        result["stream_objects"]["error"] = str(e)


# ---
# STEP 4 — Forensic flag logic (the detective work)
# ---

# PDF editing tools that should NEVER appear in genuine bank-issued PDFs
_SUSPICIOUS_PRODUCERS = ["Foxit", "ilovepdf", "Smallpdf", "PDFescape", "pdf24"]


def _apply_forensic_flags(result: dict):
    """
    Apply rule-based forensic flags based on extracted metadata.
    Each flag has: severity (HIGH/MEDIUM/LOW), code, and a human-readable detail.
    """
    flags = result["forensic_flags"]
    xmp   = result["internal_xmp"]
    strm  = result["stream_objects"]

    # --- Rule 1: Creation date is AFTER modification date (impossible) ---
    c_iso = xmp.get("created_iso", "N/A")
    m_iso = xmp.get("modified_iso", "N/A")
    if c_iso != "N/A" and m_iso != "N/A":
        try:
            if datetime.fromisoformat(c_iso) > datetime.fromisoformat(m_iso):
                flags.append({
                    "severity": "HIGH",
                    "code": "DATE_INVERSION",
                    "detail": f"Creation date ({c_iso}) is AFTER modification date ({m_iso})"
                })
        except Exception:
            pass

    # --- Rule 2: Many incremental saves = heavy post-creation editing ---
    saves = strm.get("incremental_saves_count", 0)
    if saves >= 3:
        flags.append({
            "severity": "MEDIUM",
            "code": "MULTIPLE_EDITS",
            "detail": f"Document saved incrementally {saves} times — suggests repeated editing after creation"
        })

    # --- Rule 3: Known PDF editing tool found in binary ---
    editors = strm.get("editing_tools_detected", [])
    if editors:
        flags.append({
            "severity": "MEDIUM",
            "code": "EDITING_TOOL_PRESENT",
            "detail": f"PDF editor signatures found: {editors}"
        })

    # --- Rule 4: Creator ≠ Producer AND producer is a known editing site ---
    creator  = xmp.get("creator", "N/A")
    producer = xmp.get("producer", "N/A")
    if creator != "N/A" and producer != "N/A" and creator != producer:
        if any(ed in producer for ed in _SUSPICIOUS_PRODUCERS):
            flags.append({
                "severity": "HIGH",
                "code": "SUSPICIOUS_PRODUCER",
                "detail": f"Document originally from '{creator}' but re-processed by '{producer}' — known PDF editing tool"
            })

    # --- Rule 5: JavaScript in a loan document (should NEVER be there) ---
    js = strm.get("javascript_streams", 0)
    if js > 0:
        flags.append({
            "severity": "HIGH",
            "code": "JAVASCRIPT_DETECTED",
            "detail": f"{js} JavaScript stream(s) found — unusual in legitimate loan documents"
        })

    # --- Rule 6: Embedded files (hidden attachments) ---
    ef = strm.get("embedded_files", 0)
    if ef > 0:
        flags.append({
            "severity": "MEDIUM",
            "code": "EMBEDDED_FILE",
            "detail": f"{ef} embedded file object(s) — inspect manually"
        })

    # --- Rule 7: No author or creator (metadata stripped — a classic fraudster trick) ---
    if creator == "N/A" and xmp.get("author", "N/A") == "N/A":
        flags.append({
            "severity": "LOW",
            "code": "NO_AUTHORSHIP_METADATA",
            "detail": "No Author or Creator field — metadata may have been deliberately stripped"
        })
