"""
core/macro_detector.py
───────────────────────
VBA Macro Detection in Office Documents (.docx, .xlsx, .doc, .xls).

HOW MACRO ATTACKS WORK:
  1. Attacker crafts a malicious Word document with a macro
  2. Victim opens the document (e.g., a bank officer opening a "loan application")
  3. The macro runs automatically (AutoOpen / Document_Open trigger)
  4. Macro downloads and executes a second-stage payload
  5. Bank system is compromised

WHAT WE DETECT:
───────────────
1. Presence of vbaProject.bin  — the binary file that stores VBA macros
   inside the Office ZIP structure. If this file exists, macros are present.

2. Auto-execution triggers:
   AutoOpen, AutoClose, AutoExec, AutoNew — run when doc opens/closes
   Document_Open, Workbook_Open — event handlers that auto-execute

3. Obfuscation patterns:
   Shell()         — launches OS commands (classic payload execution)
   CreateObject()  — creates COM objects (used to access WScript, PowerShell)
   Chr()           — character-by-character string building (obfuscation)
   WScript         — Windows Script Host (used to run scripts)
   PowerShell      — often called to download second-stage malware
   URLDownloadToFile — downloads files from the internet

NOTE: We also handle the older .doc/.xls format (OLE compound documents)
which store macros differently — in an OLE stream called "Macros".
"""

import zipfile
import os


# ---
# DETECTION PATTERNS
# ---

# Auto-execution triggers (macro runs without user clicking anything)
AUTORUN_PATTERNS = [
    b"AutoOpen", b"AutoClose", b"AutoExec", b"AutoNew",
    b"Document_Open", b"Document_Close",
    b"Workbook_Open", b"Workbook_Close",
    b"Auto_Open", b"Auto_Close",
]

# Obfuscation and payload delivery patterns
OBFUSCATION_PATTERNS = [
    b"Shell",           # OS command execution
    b"CreateObject",    # COM object instantiation
    b"WScript",         # Windows Script Host
    b"PowerShell",      # PowerShell invocation
    b"URLDownloadToFile",  # File download from internet
    b"InternetExplorer.Application",  # Browser-based download
    b"XMLHTTP",         # HTTP request from macro
    b"Environ",         # Environment variable access (recon)
    b"GetObject",       # Access to running objects
    b"CallByName",      # Dynamic function call (obfuscation)
]


# ---
# MAIN DETECTOR
# ---

def detect_macros(filepath: str) -> dict:
    """
    Detect VBA macros and suspicious macro patterns in Office documents.

    Supports: .docx, .xlsx, .doc, .xls (and any Office Open XML format)

    Returns:
        macros_present      : bool
        vba_project_found   : bool  — vbaProject.bin found in ZIP
        autorun_triggers    : list  — auto-execution keywords found
        obfuscation_found   : list  — suspicious capability keywords found
        ole_macros_detected : bool  — old .doc/.xls macro stream found
        forensic_flags      : list
    """
    result = {
        "macros_present":      False,
        "vba_project_found":   False,
        "autorun_triggers":    [],
        "obfuscation_found":   [],
        "ole_macros_detected": False,
        "forensic_flags":      []
    }

    ext = os.path.splitext(filepath)[1].lower()

    # --- Modern Office formats (.docx, .xlsx) — ZIP-based ---
    if ext in (".docx", ".xlsx", ".pptx", ".dotm", ".xlsm"):
        _scan_ooxml_macros(filepath, result)

    # --- Legacy Office formats (.doc, .xls) — OLE-based ---
    elif ext in (".doc", ".xls", ".ppt"):
        _scan_ole_macros(filepath, result)

    # --- Raw binary scan for ANY file type ---
    # Always run — catches macros in mislabeled files
    _scan_binary_macros(filepath, result)

    # Aggregate: if any macro presence found, mark macros_present = True
    if (result["vba_project_found"] or
            result["autorun_triggers"] or
            result["ole_macros_detected"]):
        result["macros_present"] = True

    _apply_macro_flags(result)
    return result


# ---
# SCANNER: OOXML (Modern Office — ZIP Structure)
# ---

def _scan_ooxml_macros(filepath: str, result: dict):
    """
    Unzip the Office document and look for vbaProject.bin.
    This binary file is ONLY present if the document contains VBA macros.
    Its presence is a definitive indicator — not a false positive.
    """
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            names = z.namelist()

            # vbaProject.bin = the VBA macro container
            vba_files = [n for n in names if "vbaproject" in n.lower()]
            if vba_files:
                result["vba_project_found"] = True

                # Read the VBA binary and scan for dangerous patterns
                for vba_file in vba_files:
                    try:
                        vba_data = z.read(vba_file)
                        _scan_vba_content(vba_data, result)
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        pass   # Not a ZIP — handled elsewhere
    except Exception as e:
        result["ooxml_scan_error"] = str(e)


# ---
# SCANNER: OLE (Legacy Office — .doc, .xls)
# ---

def _scan_ole_macros(filepath: str, result: dict):
    """
    Detect macros in old-format .doc/.xls files (OLE compound documents).
    These files start with the OLE magic bytes: D0 CF 11 E0.
    The macro stream is stored in a sub-stream named 'Macros' or 'VBA'.
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # OLE magic bytes check
        if raw[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return

        # Look for VBA/Macro stream signatures in the OLE binary
        ole_macro_sigs = [b"VBA", b"Macros", b"\x41\x74\x74\x72\x69\x62\x75\x74\x65"]
        if any(sig in raw for sig in ole_macro_sigs):
            result["ole_macros_detected"] = True
            _scan_vba_content(raw, result)

    except Exception as e:
        result["ole_scan_error"] = str(e)


# ---
# SCANNER: Binary pattern scan (runs on all file types)
# ---

def _scan_binary_macros(filepath: str, result: dict):
    """
    Raw binary scan for macro-related strings.
    Catches cases where macros appear in mislabeled or unusual file formats.
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        _scan_vba_content(raw, result)
    except Exception:
        pass


def _scan_vba_content(data: bytes, result: dict):
    """
    Scan a binary blob for autorun triggers and obfuscation patterns.
    Populates result['autorun_triggers'] and result['obfuscation_found'].
    """
    # Check autorun patterns (case-insensitive by also checking lowercase)
    for pattern in AUTORUN_PATTERNS:
        if (pattern in data or pattern.lower() in data) and \
                pattern.decode("utf-8", errors="ignore") not in result["autorun_triggers"]:
            result["autorun_triggers"].append(pattern.decode("utf-8", errors="ignore"))

    # Check obfuscation/capability patterns
    for pattern in OBFUSCATION_PATTERNS:
        if (pattern in data or pattern.lower() in data) and \
                pattern.decode("utf-8", errors="ignore") not in result["obfuscation_found"]:
            result["obfuscation_found"].append(pattern.decode("utf-8", errors="ignore"))


# ---
# FORENSIC FLAG LOGIC
# ---

def _apply_macro_flags(result: dict):
    flags = result["forensic_flags"]

    # Rule 1: vbaProject.bin found = macros are DEFINITELY present
    if result["vba_project_found"]:
        flags.append({
            "severity": "HIGH",
            "code":     "VBA_MACRO_DETECTED",
            "detail":   (
                "vbaProject.bin found inside the Office document — "
                "this file contains executable VBA macros. "
                "Macros in bank documents are a major red flag and a known malware vector."
            )
        })

    # Rule 2: OLE macro stream found in legacy format
    if result["ole_macros_detected"]:
        flags.append({
            "severity": "HIGH",
            "code":     "OLE_MACRO_DETECTED",
            "detail":   (
                "Macro stream detected in legacy Office format (.doc/.xls). "
                "Old-format Office macros are frequently used in banking malware attacks."
            )
        })

    # Rule 3: Auto-execution trigger found
    if result["autorun_triggers"]:
        flags.append({
            "severity": "HIGH",
            "code":     "MACRO_AUTORUN",
            "detail":   (
                f"Auto-execution trigger(s) found: {result['autorun_triggers']}. "
                f"These macros run AUTOMATICALLY when the document is opened — "
                f"no user interaction required."
            )
        })

    # Rule 4: Obfuscation / dangerous capabilities
    if result["obfuscation_found"]:
        flags.append({
            "severity": "MEDIUM",
            "code":     "MACRO_SUSPICIOUS_CAPABILITIES",
            "detail":   (
                f"Suspicious macro capabilities detected: {result['obfuscation_found'][:5]}. "
                f"These are commonly used in macro-based malware for payload execution "
                f"and data exfiltration."
            )
        })
