#!/usr/bin/env python3

import sys
import json
import argparse
from pathlib import Path

# --- Make sure the project root is on the path ---
sys.path.insert(0, str(Path(__file__).parent))

from core import extract_metadata, verify_ledger_integrity


# ---
# PRETTY REPORT PRINTER
# ---

SEVERITY_ICON = {"HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[i]"}
RISK_COLOR    = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[31m",   # red
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      "\033[34m",   # blue
    "CLEAN":    "\033[32m",   # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_report(meta: dict):
    """Print a formatted forensic report to the terminal."""

    W = 70
    print("\n" + "-" * W)
    print(f"{BOLD}  PaperTrail AI - Forensics Report{RESET}")
    print("-" * W)
    print(f"  File      : {meta.get('source_file', 'N/A')}")
    print(f"  Type      : {meta.get('file_type', 'N/A')}")
    print(f"  SHA-256   : {meta.get('sha256', 'N/A')}")
    print(f"  Size      : {meta.get('file_size_bytes', 0):,} bytes")
    print(f"  Extracted : {meta.get('extracted_at', 'N/A')}")

    # --- Ledger result ---
    lr = meta.get("ledger_result", {})
    lr_status = lr.get("status", "N/A")
    lr_icon = {
        "REGISTERED":           "",
        "DUPLICATE_SUBMISSION": "",
        "HASH_MISMATCH":        "",
    }.get(lr_status, "")
    print(f"\n  Ledger    : {lr_icon} {lr_status}")
    if lr_status != "REGISTERED":
        print(f"             {lr.get('detail', '')}")

    # --- Risk score bar ---
    ra    = meta.get("risk_assessment", {})
    score = ra.get("risk_score", 0)
    level = ra.get("risk_level", "N/A")
    color = RISK_COLOR.get(level, "")
    filled = score // 5
    bar    = "█" * filled + "░" * (20 - filled)
    print(f"\n  {BOLD}RISK SCORE : [{color}{bar}{RESET}{BOLD}] {color}{score}/100  →  {level}{RESET}")
    print(f"  Flags      : "
          f"{ra.get('high_flags', 0)} HIGH  |  "
          f"{ra.get('medium_flags', 0)} MEDIUM  |  "
          f"{ra.get('low_flags', 0)} LOW")

    # --- Standard metadata sections ---
    sections = [
        ("PDF INFO",           "pdfinfo"),
        ("DOCUMENT METADATA",  "internal_xmp"),
        ("CORE PROPERTIES",    "core_properties"),
        ("APP PROPERTIES",     "app_properties"),
        ("REVISION HISTORY",   "revision_history"),
        ("IMAGE PROPERTIES",   "basic_properties"),
        ("EXIF DATA",          "exif_data"),
        ("COMPRESSION",        "compression_analysis"),
        ("EXIFTOOL EXTRAS",    "exiftool_extras"),
        ("STREAM OBJECTS",     "stream_objects"),
    ]
    for label, key in sections:
        data = meta.get(key)
        if not data:
            continue
        visible = {k: v for k, v in data.items()
                   if v not in (None, "N/A", "", [], {}, False)}
        if not visible:
            continue
        print(f"\n  --- {label} ---")
        for k, v in visible.items():
            print(f"     {k:<28} {v}")

    # --- Cybersecurity analysis sections ---
    _print_magic_bytes(meta.get("magic_bytes", {}))
    _print_entropy(meta.get("entropy_analysis", {}))
    _print_iocs(meta.get("ioc_analysis", {}))
    _print_macros(meta.get("macro_analysis"))
    _print_stego(meta.get("stego_analysis"))

    # --- Forensic flags ---
    flags = meta.get("forensic_flags", [])
    if flags:
        print(f"\n  --- Forensic Flags  ({len(flags)} detected) ---")
        for f in flags:
            icon = SEVERITY_ICON.get(f["severity"], "[?]")
            sev  = f["severity"]
            col  = RISK_COLOR.get(sev, "")
            print(f"     {icon} {col}[{sev}]{RESET} {BOLD}{f['code']}{RESET}")
            print(f"          {f['detail']}")
    else:
        print("\n  --- Forensic Flags ---")
        print("     \033[32mNo anomalies detected — document appears clean\033[0m")

    print("\n" + "-" * W + "\n")


# ---
# CYBERSECURITY SECTION PRINTERS
# ---

def _print_magic_bytes(data: dict):
    """Print magic bytes / file signature validation results."""
    if not data or "error" in data:
        return
    print(f"\n  --- MAGIC BYTES (File Signature) ---")
    ext       = data.get("claimed_extension", "N/A")
    detected  = data.get("detected_formats", [])
    valid     = data.get("extension_valid", True)
    status    = f"\033[32mVALID\033[0m" if valid else f"\033[91mMISMATCH\033[0m"
    print(f"     {'Claimed extension':<28} {ext}")
    print(f"     {'Detected format(s)':<28} {detected if detected else 'None matched'}")
    print(f"     {'Signature valid':<28} {status}")


def _print_entropy(data: dict):
    """Print Shannon entropy analysis results."""
    if not data or "error" in data:
        return
    overall = data.get("overall_entropy", 0.0)
    header  = data.get("header_entropy", 0.0)
    chunks  = data.get("high_entropy_chunks", 0)
    total   = data.get("total_chunks", 0)
    ratio   = data.get("suspicious_ratio", 0.0)

    # Color-code entropy level
    if overall >= 7.8:
        e_color = "\033[91m"   # bright red — very high
    elif overall >= 7.0:
        e_color = "\033[33m"   # yellow — elevated
    else:
        e_color = "\033[32m"   # green — normal
    print(f"\n  --- ENTROPY ANALYSIS (Shannon) ---")
    print(f"     {'Overall entropy':<28} {e_color}{overall:.4f} / 8.0000\033[0m")
    print(f"     {'Header entropy':<28} {header:.4f} / 8.0000")
    if total > 0:
        print(f"     {'High-entropy sections':<28} {chunks} / {total} blocks ({ratio*100:.1f}%)")


def _print_iocs(data: dict):
    """Print IOC (Indicator of Compromise) extraction results."""
    if not data or "error" in data:
        return
    urls   = data.get("urls_found", [])
    ips    = data.get("ips_found", [])
    emails = data.get("emails_found", [])
    if not urls and not ips and not emails:
        return
    print(f"\n  --- IOC EXTRACTION (Embedded Indicators) ---")
    if urls:
        print(f"     {'URLs found':<28} {len(urls)}")
        for u in urls[:3]:
            print(f"       {'→':<27} {u[:80]}")
        if len(urls) > 3:
            print(f"       {'→':<27} ... and {len(urls)-3} more")
    if ips:
        print(f"     {'Public IPs found':<28} {ips[:5]}")
    if emails:
        print(f"     {'Email addresses found':<28} {len(emails)}")


def _print_macros(data: dict):
    """Print macro detection results (Office documents only)."""
    if not data:
        return
    present   = data.get("macros_present", False)
    vba       = data.get("vba_project_found", False)
    ole       = data.get("ole_macros_detected", False)
    autorun   = data.get("autorun_triggers", [])
    obfuscate = data.get("obfuscation_found", [])

    icon = "\033[91mMACROS DETECTED\033[0m" if present else "\033[32mNo macros\033[0m"
    print(f"\n  --- MACRO DETECTION (VBA) ---")
    print(f"     {'Status':<28} {icon}")
    if vba:
        print(f"     {'vbaProject.bin':<28} \033[91mFOUND — executable macros present\033[0m")
    if ole:
        print(f"     {'OLE macro stream':<28} \033[91mFOUND — legacy format macros\033[0m")
    if autorun:
        print(f"     {'Auto-run triggers':<28} \033[91m{autorun}\033[0m")
    if obfuscate:
        print(f"     {'Suspicious keywords':<28} {obfuscate[:4]}")


def _print_stego(data: dict):
    """Print steganography detection results (images only)."""
    if not data:
        return
    if "error" in data or "note" in data:
        return
    pixels    = data.get("pixels_analyzed", 0)
    lsb_ratio = data.get("lsb_ratio", 0.0)
    chi_p     = data.get("chi_square_p", 1.0)
    suspected = data.get("stego_suspected", False)
    capacity  = data.get("capacity_estimate", "N/A")

    icon = "\033[91mSUSPECTED\033[0m" if suspected else "\033[32mNot detected\033[0m"
    print(f"\n  ---  STEGANOGRAPHY DETECTION (LSB) ---")
    print(f"     {'Status':<28} {icon}")
    print(f"     {'Pixels analyzed':<28} {pixels:,}")
    print(f"     {'LSB bit ratio':<28} {lsb_ratio:.4f}  (0.50 = suspicious)")
    print(f"     {'Chi-square p-value':<28} {chi_p:.4f}  (< 0.05 = suspicious)")
    print(f"     {'Stego capacity':<28} {capacity}")


# ---
# MAIN
# ---

def main():
    parser = argparse.ArgumentParser(
        description="PaperTrail AI — Document Metadata Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py salary_slip.pdf
  python run.py land_record.docx --json
  python run.py scanned_stamp.jpg
  python run.py --verify-ledger
        """
    )
    parser.add_argument("filepath", nargs="?", help="Path to the document to analyze")
    parser.add_argument("--json",         action="store_true", help="Also output raw JSON report")
    parser.add_argument("--verify-ledger", action="store_true", help="Verify integrity of hash ledger")
    args = parser.parse_args()

    # --- Ledger verification mode ---
    if args.verify_ledger:
        result = verify_ledger_integrity()
        print("\n" + "-" * 60)
        print("  PAPERTRAIL AI — LEDGER INTEGRITY CHECK")
        print("-" * 60)
        if result["intact"]:
            print(f"  \033[32mLedger is INTACT\033[0m")
            print(f"  Merkle Root : {result['merkle_root']}")
        else:
            print(f"  \033[91mLEDGER TAMPERED — integrity check FAILED\033[0m")
            print(f"  Stored root     : {result.get('stored_root')}")
            print(f"  Recomputed root : {result.get('recomputed_root')}")
        print(f"  {result['detail']}")
        print("-" * 60 + "\n")
        return

    # --- Document analysis mode ---
    if not args.filepath:
        parser.print_help()
        sys.exit(1)

    filepath = args.filepath
    if not Path(filepath).exists():
        print(f"\n Error: File not found — {filepath}\n")
        sys.exit(1)

    print(f"\n Analyzing: {filepath} ...")
    meta = extract_metadata(filepath)

    if "error" in meta:
        print(f"\n {meta['error']}\n")
        sys.exit(1)

    print_report(meta)

    # Always save JSON report to reports/ folder
    report_dir = Path(__file__).parent / "reports"
    report_dir.mkdir(exist_ok=True)
    stem       = Path(filepath).stem
    out_json   = report_dir / f"{stem}_forensics.json"

    with open(out_json, "w") as jf:
        json.dump(meta, jf, indent=2, default=str)
    print(f"   JSON report saved → {out_json}\n")

    # Print raw JSON to terminal if requested
    if args.json:
        print(json.dumps(meta, indent=2, default=str))


if __name__ == "__main__":
    main()
