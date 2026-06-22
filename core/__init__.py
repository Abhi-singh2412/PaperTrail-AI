
from .pdf_forensics    import extract_pdf_metadata
from .docx_forensics   import extract_docx_metadata
from .image_forensics  import extract_image_metadata
from .risk_scorer      import compute_risk_score
from .hash_ledger      import register_document, verify_ledger_integrity
from .utils            import sha256_hash

# --- New cybersecurity modules ---
from .entropy_analyzer import analyze_entropy
from .magic_bytes      import validate_magic_bytes
from .ioc_extractor    import extract_iocs
from .macro_detector   import detect_macros
from .stego_detector   import detect_steganography

from datetime import datetime, timezone
from pathlib import Path


# ---
# FILE TYPE ROUTING
# ---

_IMAGE_EXTS    = {".jpg", ".jpeg", ".png", ".tiff", ".bmp"}
_DOCUMENT_EXTS = {".pdf", ".docx", ".doc", ".xlsx", ".xls"}


def extract_metadata(filepath: str) -> dict:
    """
    Main dispatcher — detects file type, runs the correct extractor,
    and enriches the result with all cybersecurity analysis layers.

    Pipeline per file:
        1. Format-specific metadata extraction (PDF / DOCX / Image)
        2. Magic bytes validation            (file type spoofing)
        3. Shannon entropy analysis          (hidden/encrypted content)
        4. IOC extraction                    (embedded URLs / IPs / emails)
        5. Macro detection                   (VBA macros — Office only)
        6. Steganography detection           (LSB analysis — images only)
        7. Hash ledger registration          (re-submission / tamper check)
        8. Risk score computation            (aggregated from all flags)
    """
    ext = Path(filepath).suffix.lower()

    # --- Step 1: Format-specific metadata extraction ---
    if ext == ".pdf":
        meta = extract_pdf_metadata(filepath)
    elif ext in (".docx", ".doc", ".xlsx", ".xls"):
        meta = extract_docx_metadata(filepath)
    elif ext in _IMAGE_EXTS:
        meta = extract_image_metadata(filepath)
    else:
        return {"error": f"Unsupported file type: {ext}"}

    # --- Step 2: Magic bytes validation (ALL file types) ---
    magic_result = validate_magic_bytes(filepath)
    meta["magic_bytes"]        = magic_result
    meta["forensic_flags"].extend(magic_result.get("forensic_flags", []))

    # --- Step 3: Shannon entropy analysis (ALL file types) ---
    entropy_result = analyze_entropy(filepath)
    meta["entropy_analysis"]   = entropy_result
    meta["forensic_flags"].extend(entropy_result.get("forensic_flags", []))

    # --- Step 4: IOC extraction (ALL file types) ---
    ioc_result = extract_iocs(filepath)
    meta["ioc_analysis"]       = ioc_result
    meta["forensic_flags"].extend(ioc_result.get("forensic_flags", []))

    # --- Step 5: Macro detection (Office documents only) ---
    if ext in (".docx", ".doc", ".xlsx", ".xls", ".xlsm", ".dotm"):
        macro_result = detect_macros(filepath)
        meta["macro_analysis"]  = macro_result
        meta["forensic_flags"].extend(macro_result.get("forensic_flags", []))

    # --- Step 6: Steganography detection (images only) ---
    if ext in _IMAGE_EXTS:
        stego_result = detect_steganography(filepath)
        meta["stego_analysis"]  = stego_result
        meta["forensic_flags"].extend(stego_result.get("forensic_flags", []))

    # --- Step 7: Hash ledger (ALL file types) ---
    meta["ledger_result"] = register_document(filepath, meta["sha256"])
    if meta["ledger_result"].get("status") == "HASH_MISMATCH":
        meta["forensic_flags"].append({
            "severity": "HIGH",
            "code":     "HASH_MISMATCH_RESUBMISSION",
            "detail":   meta["ledger_result"]["detail"]
        })

    # --- Step 8: Final risk score (all flags aggregated) ---
    meta["risk_assessment"] = compute_risk_score(meta)
    meta["extracted_at"]    = datetime.now(timezone.utc).isoformat()
    return meta


__all__ = [
    "extract_metadata",
    "extract_pdf_metadata",
    "extract_docx_metadata",
    "extract_image_metadata",
    "compute_risk_score",
    "register_document",
    "verify_ledger_integrity",
    "sha256_hash",
    "analyze_entropy",
    "validate_magic_bytes",
    "extract_iocs",
    "detect_macros",
    "detect_steganography",
]
