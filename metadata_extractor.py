import os
import sys
import json
import hashlib
import subprocess
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---
# UTILITY HELPERS
# ---

def sha256_hash(filepath: str) -> str:
    """Compute SHA-256 hash of entire file (for Merkle ledger anchoring)."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_str(val) -> str:
    if val is None:
        return "N/A"
    return str(val).strip()

def parse_pdf_date(raw: str) -> str:
    """
    Convert PDF date format D:YYYYMMDDHHmmSSOHH'mm' to ISO string.
    Returns 'N/A' on failure.
    """
    if not raw or raw == "N/A":
        return "N/A"
    raw = raw.strip().lstrip("D:").split("+")[0].split("-")[0].split("Z")[0]
    raw = raw.replace("'", "")
    fmts = ["%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d"]
    for fmt in fmts:
        try:
            return datetime.strptime(raw[:len(fmt.replace("%","XX").replace("X",""))], fmt).isoformat()
        except Exception:
            pass
    return raw  # return raw if parsing fails

def days_between(date_str1: str, date_str2: str) -> Any:
    """Return number of days between two ISO date strings."""
    try:
        d1 = datetime.fromisoformat(date_str1.split("T")[0])
        d2 = datetime.fromisoformat(date_str2.split("T")[0])
        return abs((d2 - d1).days)
    except Exception:
        return None


# ---
# MODULE 1: PDF METADATA EXTRACTOR
# ---

def extract_pdf_metadata(filepath: str) -> dict:
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

    # --- 1a. pdfinfo (system tool) ---
    try:
        out = subprocess.check_output(
            ["pdfinfo", filepath], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                result["pdfinfo"][key.strip()] = val.strip()
    except Exception as e:
        result["pdfinfo"]["error"] = str(e)

    # --- 1b. pypdf deep reader ---
    try:
        from pypdf import PdfReader
        reader = PdfReader(filepath)
        meta = reader.metadata or {}

        fields = {
            "title":        meta.get("/Title"),
            "author":       meta.get("/Author"),
            "subject":      meta.get("/Subject"),
            "creator":      meta.get("/Creator"),       # app that made the source doc
            "producer":     meta.get("/Producer"),      # PDF renderer / converter
            "created":      meta.get("/CreationDate"),
            "modified":     meta.get("/ModDate"),
            "keywords":     meta.get("/Keywords"),
            "trapped":      meta.get("/Trapped"),
        }

        # Parse dates
        fields["created_iso"]  = parse_pdf_date(safe_str(fields["created"]))
        fields["modified_iso"] = parse_pdf_date(safe_str(fields["modified"]))

        result["internal_xmp"] = {k: safe_str(v) for k, v in fields.items()}
        result["internal_xmp"]["page_count"] = len(reader.pages)
        result["internal_xmp"]["is_encrypted"] = reader.is_encrypted

        # Check XMP stream for extra metadata
        try:
            xmp = reader.xmp_metadata
            if xmp:
                result["internal_xmp"]["xmp_present"] = True
                result["internal_xmp"]["xmp_dc_format"] = safe_str(
                    getattr(xmp, "dc_format", None)
                )
        except Exception:
            result["internal_xmp"]["xmp_present"] = False

    except Exception as e:
        result["internal_xmp"]["error"] = str(e)

    # --- 1c. Raw binary scan for stream anomalies ---
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # Count JavaScript streams (fraud vector: hidden JS in PDFs)
        js_count = raw.count(b"/JavaScript") + raw.count(b"/JS")
        # Count embedded file streams
        ef_count = raw.count(b"/EmbeddedFile")
        # Count launch actions (can trigger external processes)
        launch_count = raw.count(b"/Launch")
        # Detect if PDF was created by a scanner (GoodScan, ScanSnap, etc.)
        scanner_hints = [b"ScanSnap", b"EPSON", b"Canon", b"HP Scan", b"Xerox", b"KONICA"]
        scanner_found = any(hint in raw for hint in scanner_hints)
        # Detect editing tools (suspicious for "original" bank documents)
        editing_tools = [b"Adobe Acrobat", b"Foxit", b"LibreOffice", b"PDFescape",
                         b"Smallpdf", b"ilovepdf", b"pdf24", b"PDFill", b"Nitro"]
        editors_found = [t.decode() for t in editing_tools if t in raw]
        # Count incremental saves (each save appends a new %%EOF)
        incremental_saves = raw.count(b"%%EOF") - 1  # first is original

        result["stream_objects"] = {
            "javascript_streams": js_count,
            "embedded_files": ef_count,
            "launch_actions": launch_count,
            "scanner_origin_detected": scanner_found,
            "editing_tools_detected": editors_found,
            "incremental_saves_count": max(0, incremental_saves),
        }
    except Exception as e:
        result["stream_objects"]["error"] = str(e)

    # --- 1d. Forensic flag logic ---
    flags = result["forensic_flags"]
    xmp   = result["internal_xmp"]
    strm  = result["stream_objects"]

    # Flag: Creation date AFTER modification date (impossible on genuine doc)
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

    # Flag: Modified many times (many incremental saves = heavy editing)
    if strm.get("incremental_saves_count", 0) >= 3:
        flags.append({
            "severity": "MEDIUM",
            "code": "MULTIPLE_EDITS",
            "detail": f"Document saved incrementally {strm['incremental_saves_count']} times — suggests repeated editing after creation"
        })

    # Flag: Editing tool found in a document claiming to be bank-issued
    if strm.get("editing_tools_detected"):
        flags.append({
            "severity": "MEDIUM",
            "code": "EDITING_TOOL_PRESENT",
            "detail": f"PDF editor signatures found: {strm['editing_tools_detected']}"
        })

    # Flag: Creator ≠ Producer (source app ≠ PDF engine — may indicate re-save)
    creator  = xmp.get("creator", "N/A")
    producer = xmp.get("producer", "N/A")
    if creator != "N/A" and producer != "N/A" and creator != producer:
        if any(ed in producer for ed in ["Foxit", "ilovepdf", "Smallpdf", "PDFescape", "pdf24"]):
            flags.append({
                "severity": "HIGH",
                "code": "SUSPICIOUS_PRODUCER",
                "detail": f"Document originally from '{creator}' but re-processed by '{producer}' — known PDF editing tool"
            })

    # Flag: JavaScript in PDF (highly suspicious for a loan document)
    if strm.get("javascript_streams", 0) > 0:
        flags.append({
            "severity": "HIGH",
            "code": "JAVASCRIPT_DETECTED",
            "detail": f"{strm['javascript_streams']} JavaScript stream(s) found — unusual in legitimate loan documents"
        })

    # Flag: Embedded files
    if strm.get("embedded_files", 0) > 0:
        flags.append({
            "severity": "MEDIUM",
            "code": "EMBEDDED_FILE",
            "detail": f"{strm['embedded_files']} embedded file object(s) — inspect manually"
        })

    # Flag: No author or creator (common in auto-generated forged PDFs)
    if creator == "N/A" and xmp.get("author", "N/A") == "N/A":
        flags.append({
            "severity": "LOW",
            "code": "NO_AUTHORSHIP_METADATA",
            "detail": "No Author or Creator field — metadata may have been deliberately stripped"
        })

    return result


# ---
# MODULE 2: DOCX METADATA EXTRACTOR
# ---

def extract_docx_metadata(filepath: str) -> dict:
    result = {
        "file_type": "DOCX",
        "source_file": os.path.basename(filepath),
        "sha256": sha256_hash(filepath),
        "file_size_bytes": os.path.getsize(filepath),
        "core_properties": {},
        "app_properties": {},
        "revision_history": {},
        "forensic_flags": []
    }

    try:
        from docx import Document
        doc = Document(filepath)
        cp = doc.core_properties

        result["core_properties"] = {
            "title":           safe_str(cp.title),
            "author":          safe_str(cp.author),
            "last_modified_by": safe_str(cp.last_modified_by),
            "created":         cp.created.isoformat() if cp.created else "N/A",
            "modified":        cp.modified.isoformat() if cp.modified else "N/A",
            "revision":        safe_str(cp.revision),
            "category":        safe_str(cp.category),
            "subject":         safe_str(cp.subject),
            "keywords":        safe_str(cp.keywords),
            "language":        safe_str(cp.language),
            # description field removed (not in all versions)
            "content_status":  safe_str(cp.content_status),
        }
    except Exception as e:
        result["core_properties"]["error"] = str(e)

    # --- app.xml for detailed software info ---
    try:
        with zipfile.ZipFile(filepath) as z:
            if "docProps/app.xml" in z.namelist():
                app_xml = z.read("docProps/app.xml").decode("utf-8", errors="replace")
                def xml_val(tag, text):
                    m = re.search(rf"<(?:[^:>]+:)?{tag}[^>]*>(.*?)</", text, re.DOTALL)
                    return m.group(1).strip() if m else "N/A"

                result["app_properties"] = {
                    "application":      xml_val("Application", app_xml),
                    "app_version":      xml_val("AppVersion", app_xml),
                    "company":          xml_val("Company", app_xml),
                    "total_time_mins":  xml_val("TotalTime", app_xml),  # minutes spent editing
                    "pages":            xml_val("Pages", app_xml),
                    "words":            xml_val("Words", app_xml),
                    "paragraphs":       xml_val("Paragraphs", app_xml),
                    "doc_security":     xml_val("DocSecurity", app_xml),
                }

            # Check for revision history in document.xml
            if "word/document.xml" in z.namelist():
                doc_xml = z.read("word/document.xml").decode("utf-8", errors="replace")
                revision_marks = len(re.findall(r'<w:ins |<w:del ', doc_xml))
                result["revision_history"]["tracked_changes_count"] = revision_marks
                # Look for rsid (revision save IDs) — each unique rsid = one save session
                rsids = set(re.findall(r'w:rsid(?:R|RPr|Del|Default)?="([^"]+)"', doc_xml))
                result["revision_history"]["unique_edit_sessions"] = len(rsids)
    except Exception as e:
        result["app_properties"]["error"] = str(e)

    # --- Forensic flags ---
    flags   = result["forensic_flags"]
    cp      = result["core_properties"]
    app     = result["app_properties"]
    rev     = result["revision_history"]

    # Flag: Author ≠ Last Modified By (document was handed off or tampered)
    author = cp.get("author", "N/A")
    last_by = cp.get("last_modified_by", "N/A")
    if author != "N/A" and last_by != "N/A" and author != last_by:
        flags.append({
            "severity": "MEDIUM",
            "code": "AUTHOR_MODIFIED_BY_MISMATCH",
            "detail": f"Original author '{author}' differs from last editor '{last_by}'"
        })

    # Flag: Very high revision number (repeated editing)
    try:
        rev_num = int(cp.get("revision", "0"))
        if rev_num > 20:
            flags.append({
                "severity": "MEDIUM",
                "code": "HIGH_REVISION_COUNT",
                "detail": f"Revision number is {rev_num} — document has been saved {rev_num} times"
            })
    except Exception:
        pass

    # Flag: TotalTime very low (document likely auto-generated/copied in seconds)
    try:
        tt = int(app.get("total_time_mins", "-1"))
        if 0 <= tt <= 1:
            flags.append({
                "severity": "MEDIUM",
                "code": "ZERO_EDIT_TIME",
                "detail": f"Total editing time: {tt} minute(s) — document may be auto-generated or copy-pasted"
            })
    except Exception:
        pass

    # Flag: Tracked changes (inserted/deleted text hidden in document)
    tc = rev.get("tracked_changes_count", 0)
    if tc > 0:
        flags.append({
            "severity": "MEDIUM",
            "code": "TRACKED_CHANGES_PRESENT",
            "detail": f"{tc} tracked change mark(s) found — document contains hidden insertions or deletions"
        })

    # Flag: Many edit sessions
    es = rev.get("unique_edit_sessions", 0)
    if es > 10:
        flags.append({
            "severity": "LOW",
            "code": "MANY_EDIT_SESSIONS",
            "detail": f"{es} unique edit session IDs (rsids) detected — document edited across many sessions"
        })

    # Flag: Creation before modification (sanity check)
    c_str = cp.get("created", "N/A")
    m_str = cp.get("modified", "N/A")
    if c_str != "N/A" and m_str != "N/A":
        try:
            if datetime.fromisoformat(c_str) > datetime.fromisoformat(m_str):
                flags.append({
                    "severity": "HIGH",
                    "code": "DATE_INVERSION",
                    "detail": f"Created ({c_str}) is after Modified ({m_str}) — impossible timeline"
                })
        except Exception:
            pass

    return result


# ---
# MODULE 3: IMAGE (JPEG/PNG) METADATA EXTRACTOR
# ---

def extract_image_metadata(filepath: str) -> dict:
    result = {
        "file_type": "IMAGE",
        "source_file": os.path.basename(filepath),
        "sha256": sha256_hash(filepath),
        "file_size_bytes": os.path.getsize(filepath),
        "basic_properties": {},
        "exif_data": {},
        "compression_analysis": {},
        "forensic_flags": []
    }

    # --- Basic image properties via Pillow ---
    try:
        from PIL import Image
        img = Image.open(filepath)
        result["basic_properties"] = {
            "format":       img.format,
            "mode":         img.mode,
            "width_px":     img.size[0],
            "height_px":    img.size[1],
            "dpi":          str(img.info.get("dpi", "N/A")),
            "has_icc":      "icc_profile" in img.info,
        }

        # JPEG quality estimation
        if img.format == "JPEG":
            try:
                qtables = img.quantization
                # Estimate quality from luminance table (table 0)
                avg_q = sum(qtables[0]) / len(qtables[0])
                # JPEG quality roughly: quality ≈ (100 - avg_q/16*10) — rough heuristic
                est_quality = max(1, min(100, int(100 - (avg_q - 1) * 0.8)))
                result["compression_analysis"]["jpeg_est_quality"] = est_quality
                result["compression_analysis"]["quantization_tables"] = len(qtables)
                if est_quality < 60:
                    result["forensic_flags"].append({
                        "severity": "MEDIUM",
                        "code": "LOW_JPEG_QUALITY",
                        "detail": f"Estimated JPEG quality ~{est_quality}% — heavy compression may hide splicing artifacts"
                    })
            except Exception:
                pass
    except Exception as e:
        result["basic_properties"]["error"] = str(e)

    # --- EXIF via exifread ---
    try:
        import exifread
        with open(filepath, "rb") as f:
            tags = exifread.process_file(f, stop_tag="UNDEF", details=False)

        def tag(name):
            return str(tags.get(name, "N/A"))

        result["exif_data"] = {
            "make":              tag("Image Make"),
            "model":             tag("Image Model"),
            "software":          tag("Image Software"),
            "datetime_original": tag("EXIF DateTimeOriginal"),
            "datetime_digitized":tag("EXIF DateTimeDigitized"),
            "datetime_modified": tag("Image DateTime"),
            "gps_latitude":      tag("GPS GPSLatitude"),
            "gps_longitude":     tag("GPS GPSLongitude"),
            "gps_altitude":      tag("GPS GPSAltitude"),
            "user_comment":      tag("EXIF UserComment"),
            "document_name":     tag("Image DocumentName"),
            "image_description": tag("Image ImageDescription"),
            "copyright":         tag("Image Copyright"),
            "artist":            tag("Image Artist"),
            "x_resolution":      tag("Image XResolution"),
            "y_resolution":      tag("Image YResolution"),
            "color_space":       tag("EXIF ColorSpace"),
            "flash":             tag("EXIF Flash"),
            "exposure_time":     tag("EXIF ExposureTime"),
            "f_number":          tag("EXIF FNumber"),
            "iso_speed":         tag("EXIF ISOSpeedRatings"),
        }
    except Exception as e:
        result["exif_data"]["error"] = str(e)

    # ── ExifTool for richer metadata (cross-validates above) ─
    try:
        out = subprocess.check_output(
            ["exiftool", "-json", "-a", "-u", filepath],
            stderr=subprocess.DEVNULL, text=True
        )
        etdata = json.loads(out)[0] if out.strip() else {}
        keys_of_interest = [
            "FileModifyDate", "FileCreateDate", "CreateDate",
            "ModifyDate", "MetadataDate", "HistoryWhen",
            "OriginalDocumentID", "DocumentID", "InstanceID",
            "CreatorTool", "Producer", "PDFVersion",
            "XMPToolkit", "HistoryAction", "HistorySoftwareAgent"
        ]
        result["exiftool_extras"] = {k: str(etdata[k]) for k in keys_of_interest if k in etdata}
    except Exception as e:
        result["exiftool_extras"] = {"error": str(e)}

    # --- Forensic flags ---
    flags = result["forensic_flags"]
    exif  = result["exif_data"]
    basic = result["basic_properties"]
    et    = result.get("exiftool_extras", {})

    # Flag: Editing software in EXIF (Photoshop, GIMP, etc.)
    suspicious_software = ["Photoshop", "GIMP", "Pixelmator", "Affinity", "Canva",
                           "Paint.NET", "Snapseed", "LightRoom", "Acrobat"]
    sw = exif.get("software", "N/A") + et.get("CreatorTool", "")
    found_sw = [s for s in suspicious_software if s.lower() in sw.lower()]
    if found_sw:
        flags.append({
            "severity": "HIGH",
            "code": "EDITING_SOFTWARE_IN_EXIF",
            "detail": f"Image edited with: {found_sw} — not consistent with a scanned original"
        })

    # Flag: GPS data in a scanned document (scanned docs shouldn't have GPS)
    if exif.get("gps_latitude", "N/A") != "N/A":
        flags.append({
            "severity": "LOW",
            "code": "GPS_METADATA_PRESENT",
            "detail": "GPS coordinates embedded — document was photographed with a mobile device"
        })

    # Flag: Date inconsistency between EXIF timestamps
    dt_orig  = exif.get("datetime_original", "N/A")
    dt_modif = exif.get("datetime_modified", "N/A")
    if dt_orig != "N/A" and dt_modif != "N/A" and dt_orig != dt_modif:
        try:
            d1 = datetime.strptime(dt_orig[:19],  "%Y:%m:%d %H:%M:%S")
            d2 = datetime.strptime(dt_modif[:19], "%Y:%m:%d %H:%M:%S")
            if d1 > d2:
                flags.append({
                    "severity": "HIGH",
                    "code": "EXIF_DATE_INVERSION",
                    "detail": f"Original capture ({dt_orig}) is AFTER file modification ({dt_modif}) — EXIF was tampered"
                })
        except Exception:
            pass

    # Flag: DPI too low for a genuine scan (bank docs usually 200–300 DPI)
    dpi_raw = basic.get("dpi", "N/A")
    try:
        dpi_val = float(str(dpi_raw).strip("()'\" ").split(",")[0])
        if dpi_val < 100:
            flags.append({
                "severity": "MEDIUM",
                "code": "LOW_DPI",
                "detail": f"DPI = {dpi_val} — too low for a genuine document scan; may be screenshot or screenshot-then-printed"
            })
    except Exception:
        pass

    # Flag: No make/model (genuine scans always have scanner model)
    if exif.get("make", "N/A") == "N/A" and exif.get("model", "N/A") == "N/A":
        flags.append({
            "severity": "LOW",
            "code": "NO_DEVICE_SIGNATURE",
            "detail": "No camera/scanner make or model found in EXIF — metadata may have been stripped"
        })

    return result


# ---
# MODULE 4: RISK SCORE CALCULATOR
# ---

SEVERITY_WEIGHTS = {"HIGH": 40, "MEDIUM": 20, "LOW": 5}

def compute_risk_score(metadata: dict) -> dict:
    flags    = metadata.get("forensic_flags", [])
    raw_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in flags)
    capped    = min(raw_score, 100)

    if capped >= 70:
        level = "CRITICAL"
    elif capped >= 40:
        level = "HIGH"
    elif capped >= 20:
        level = "MEDIUM"
    elif capped > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return {
        "risk_score": capped,
        "risk_level": level,
        "flags_count": len(flags),
        "high_flags":   sum(1 for f in flags if f["severity"] == "HIGH"),
        "medium_flags": sum(1 for f in flags if f["severity"] == "MEDIUM"),
        "low_flags":    sum(1 for f in flags if f["severity"] == "LOW"),
    }


# ---
# MAIN DISPATCHER
# ---

def extract_metadata(filepath: str) -> dict:
    ext = Path(filepath).suffix.lower()

    if ext == ".pdf":
        meta = extract_pdf_metadata(filepath)
    elif ext in (".docx", ".doc"):
        meta = extract_docx_metadata(filepath)
    elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".bmp"):
        meta = extract_image_metadata(filepath)
    else:
        return {"error": f"Unsupported file type: {ext}"}

    meta["risk_assessment"] = compute_risk_score(meta)
    meta["extracted_at"]    = datetime.now(timezone.utc).isoformat()
    return meta


def print_report(meta: dict):
    """Pretty-print the forensic report to terminal."""
    print("\n" + "-"*70)
    print("  DocGuard AI - Forensics Report")
    print("-"*70)
    print(f"  File      : {meta.get('source_file', 'N/A')}")
    print(f"  Type      : {meta.get('file_type', 'N/A')}")
    print(f"  SHA-256   : {meta.get('sha256', 'N/A')}")
    print(f"  Size      : {meta.get('file_size_bytes', 0):,} bytes")
    print(f"  Extracted : {meta.get('extracted_at', 'N/A')}")

    ra = meta.get("risk_assessment", {})
    score = ra.get("risk_score", 0)
    level = ra.get("risk_level", "N/A")
    bar   = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"\n  RISK SCORE : [{bar}] {score}/100  →  {level}")
    print(f"  Flags      : {ra.get('high_flags',0)} HIGH | "
          f"{ra.get('medium_flags',0)} MEDIUM | {ra.get('low_flags',0)} LOW")

    # Metadata sections
    sections = ["pdfinfo", "internal_xmp", "core_properties",
                "app_properties", "revision_history",
                "basic_properties", "exif_data",
                "compression_analysis", "exiftool_extras",
                "stream_objects"]
    for sec in sections:
        data = meta.get(sec)
        if data:
            print(f"\n  --- {sec.upper().replace('_',' ')} ---")
            for k, v in data.items():
                if v and v not in ("N/A", "", [], {}):
                    print(f"     {k:<30} {v}")

    flags = meta.get("forensic_flags", [])
    if flags:
        print(f"\n  --- Forensic Flags ({len(flags)}) ---")
        for f in flags:
            icon = {"HIGH": "", "MEDIUM": "", "LOW": ""}.get(f["severity"], "⚪")
            print(f"     {icon} [{f['severity']}] {f['code']}")
            print(f"          {f['detail']}")
    else:
        print("\n  --- Forensic Flags ---")
        print("     No anomalies detected")

    print("\n" + "-"*70 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 metadata_extractor.py <path_to_document>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Error: File not found — {path}")
        sys.exit(1)

    metadata = extract_metadata(path)
    print_report(metadata)

    # Also save JSON output
    out_json = path + "_forensics.json"
    with open(out_json, "w") as jf:
        json.dump(metadata, jf, indent=2, default=str)
    print(f"  Full JSON report saved → {out_json}\n")