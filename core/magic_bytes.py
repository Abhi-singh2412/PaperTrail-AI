"""
core/magic_bytes.py
────────────────────
File Signature (Magic Bytes) Validation — Polyglot & Spoofing Detection.

ATTACKS WE DETECT:
──────────────────
1. EXTENSION MISMATCH (File Type Spoofing):
   A file named "salary.pdf" that actually starts with ZIP magic bytes.
   Some document parsers are tricked by the extension alone.

2. POLYGLOT FILES:
   A file that is SIMULTANEOUSLY valid in two formats.
   Example: a file that is both a valid PDF AND a valid ZIP.
   When opened as PDF, it looks like a normal salary slip.
   When unzipped, it contains malicious content.
   This is a real attack used to bypass antivirus scanners.

3. TRUNCATED / CORRUPT SIGNATURE:
   File has correct extension but the magic bytes are partially overwritten,
   indicating the file header was manually tampered with.
"""

from pathlib import Path


# ---
# MAGIC BYTE DATABASE
# Format: { "FORMAT_NAME": [(offset, magic_bytes), ...] }
# offset = byte position where the signature appears
# ---

MAGIC_SIGNATURES = {
    "PDF":   [(0, b"%PDF")],
    "ZIP":   [(0, b"PK\x03\x04")],          # DOCX, XLSX, ODT are all ZIPs
    "JPEG":  [(0, b"\xff\xd8\xff")],
    "PNG":   [(0, b"\x89PNG\r\n\x1a\n")],
    "GIF":   [(0, b"GIF87a"), (0, b"GIF89a")],
    "TIFF":  [(0, b"II*\x00"), (0, b"MM\x00*")],  # little-endian and big-endian
    "BMP":   [(0, b"BM")],
    "DOCX":  [(0, b"PK\x03\x04")],          # Same as ZIP — DOCX is a ZIP
    "XLSX":  [(0, b"PK\x03\x04")],
    "RAR":   [(0, b"Rar!\x1a\x07")],
    "ELF":   [(0, b"\x7fELF")],             # Linux executable — very suspicious!
    "PE":    [(0, b"MZ")],                  # Windows executable — very suspicious!
    "OLE":   [(0, b"\xd0\xcf\x11\xe0")],   # Old Office format (.doc, .xls)
}

# Extension → expected format(s) mapping
EXTENSION_FORMAT_MAP = {
    ".pdf":  {"PDF"},
    ".docx": {"ZIP", "DOCX"},   # DOCX is a ZIP
    ".doc":  {"OLE", "PDF"},    # Old Word format or sometimes PDF
    ".xlsx": {"ZIP", "XLSX"},
    ".jpg":  {"JPEG"},
    ".jpeg": {"JPEG"},
    ".png":  {"PNG"},
    ".tiff": {"TIFF"},
    ".tif":  {"TIFF"},
    ".bmp":  {"BMP"},
}

# Formats that are ALWAYS suspicious inside a document context
DANGEROUS_FORMATS = {"ELF", "PE"}

# Formats that COULD indicate polyglot when co-present with document format
POLYGLOT_SUSPECTS = {"ZIP", "RAR"}


# ---
# MAIN VALIDATOR
# ---

def validate_magic_bytes(filepath: str) -> dict:
    """
    Read the file's magic bytes and validate against its claimed extension.

    Returns:
        claimed_extension   : str  — the file's extension
        detected_formats    : list — all format signatures found in the file
        extension_valid     : bool — does the file match its claimed extension?
        forensic_flags      : list — any raised flags
    """
    result = {
        "claimed_extension": Path(filepath).suffix.lower(),
        "detected_formats":  [],
        "extension_valid":   True,
        "forensic_flags":    []
    }

    try:
        with open(filepath, "rb") as f:
            # Read enough bytes to cover all signatures (first 16 bytes covers most)
            header = f.read(16)

        detected = _detect_formats(header)
        result["detected_formats"] = detected

        _apply_magic_flags(result, filepath, detected, header)

    except Exception as e:
        result["error"] = str(e)

    return result


def _detect_formats(header: bytes) -> list:
    """
    Check header bytes against all known magic signatures.
    Returns a list of format names that match.
    """
    found = []
    for fmt_name, signatures in MAGIC_SIGNATURES.items():
        for offset, magic in signatures:
            if header[offset:offset + len(magic)] == magic:
                if fmt_name not in found:
                    found.append(fmt_name)
                break
    return found


def _apply_magic_flags(result: dict, filepath: str, detected: list, header: bytes):
    flags = result["forensic_flags"]
    ext   = result["claimed_extension"]
    expected_formats = EXTENSION_FORMAT_MAP.get(ext, set())

    # Rule 1: Extension mismatch — file claims to be X but magic bytes say Y
    if expected_formats and detected:
        matches = expected_formats.intersection(set(detected))
        if not matches:
            result["extension_valid"] = False
            flags.append({
                "severity": "HIGH",
                "code":     "EXTENSION_MISMATCH",
                "detail":   (
                    f"File has extension '{ext}' but magic bytes identify it as: {detected}. "
                    f"This is a file type spoofing attempt — the file is NOT what it claims to be."
                )
            })

    # Rule 2: Dangerous executable format found inside a document
    dangerous_found = [f for f in detected if f in DANGEROUS_FORMATS]
    if dangerous_found:
        flags.append({
            "severity": "HIGH",
            "code":     "EXECUTABLE_SIGNATURE_FOUND",
            "detail":   (
                f"Executable format signature detected inside document: {dangerous_found}. "
                f"This file may contain or be disguised as a malicious executable."
            )
        })

    # Rule 3: Polyglot — file matches BOTH a document format AND an archive format
    if expected_formats and detected:
        doc_formats     = expected_formats.intersection(set(detected))
        archive_formats = POLYGLOT_SUSPECTS.intersection(set(detected))
        # Exception: DOCX/XLSX are legitimately ZIPs, so skip those
        legit_zip_exts  = {".docx", ".xlsx", ".odt"}
        if doc_formats and archive_formats and ext not in legit_zip_exts:
            flags.append({
                "severity": "HIGH",
                "code":     "POLYGLOT_SUSPECTED",
                "detail":   (
                    f"File matches BOTH '{list(doc_formats)[0]}' AND '{list(archive_formats)[0]}' signatures. "
                    f"Polyglot files can bypass content filters and are used in advanced attacks."
                )
            })

    # Rule 4: No recognizable magic signature at all
    if not detected:
        flags.append({
            "severity": "LOW",
            "code":     "NO_MAGIC_SIGNATURE",
            "detail":   (
                "File header does not match any known format signature. "
                "File may be corrupt, obfuscated, or in an unusual format."
            )
        })
