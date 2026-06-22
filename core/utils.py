"""
core/utils.py
─────────────
Shared utility functions used across all forensics modules.
"""

import hashlib
from datetime import datetime
from typing import Any


def sha256_hash(filepath: str) -> str:
    """
    Compute SHA-256 hash of an entire file.

    This is the document 'fingerprint'. If even one byte changes,
    the hash completely changes — making it impossible to tamper
    without detection.

    Used for: Merkle tree anchoring in the integrity ledger.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_str(val) -> str:
    """Convert any value to a string, returning 'N/A' for None."""
    if val is None:
        return "N/A"
    return str(val).strip()


def parse_pdf_date(raw: str) -> str:
    """
    Convert PDF date format  D:YYYYMMDDHHmmSSOHH'mm'  →  ISO 8601 string.

    PDF stores dates in a proprietary format. We normalize them so we can
    compare creation vs modification dates cleanly.

    Returns 'N/A' on failure, or the raw string if format is unrecognized.
    """
    if not raw or raw == "N/A":
        return "N/A"
    raw = raw.strip().lstrip("D:").split("+")[0].split("-")[0].split("Z")[0]
    raw = raw.replace("'", "")
    fmts = ["%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d"]
    for fmt in fmts:
        try:
            placeholder = fmt.replace("%Y", "XXXX").replace("%m", "XX").replace(
                "%d", "XX").replace("%H", "XX").replace("%M", "XX").replace("%S", "XX")
            length = len(placeholder)
            return datetime.strptime(raw[:length], fmt).isoformat()
        except Exception:
            pass
    return raw


def days_between(date_str1: str, date_str2: str) -> Any:
    """Return absolute number of days between two ISO date strings."""
    try:
        d1 = datetime.fromisoformat(date_str1.split("T")[0])
        d2 = datetime.fromisoformat(date_str2.split("T")[0])
        return abs((d2 - d1).days)
    except Exception:
        return None
