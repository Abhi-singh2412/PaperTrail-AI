
import os
import re
import zipfile
from datetime import datetime

from .utils import sha256_hash, safe_str


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

    _read_core_properties(filepath, result)
    _read_app_xml(filepath, result)
    _apply_forensic_flags(result)

    return result


def _read_core_properties(filepath: str, result: dict):
    """
    Read docProps/core.xml via python-docx.
    Key fields: author, last_modified_by, created, modified, revision number.
    """
    try:
        from docx import Document
        doc = Document(filepath)
        cp = doc.core_properties

        result["core_properties"] = {
            "title":             safe_str(cp.title),
            "author":            safe_str(cp.author),
            "last_modified_by":  safe_str(cp.last_modified_by),
            "created":           cp.created.isoformat() if cp.created else "N/A",
            "modified":          cp.modified.isoformat() if cp.modified else "N/A",
            "revision":          safe_str(cp.revision),
            "category":          safe_str(cp.category),
            "subject":           safe_str(cp.subject),
            "keywords":          safe_str(cp.keywords),
            "language":          safe_str(cp.language),
            "content_status":    safe_str(cp.content_status),
        }
    except ImportError:
        result["core_properties"]["error"] = "python-docx not installed (pip install python-docx)"
    except Exception as e:
        result["core_properties"]["error"] = str(e)


def _read_app_xml(filepath: str, result: dict):
    """
    Unzip DOCX and read:
      - docProps/app.xml  → application name, total editing time, company
      - word/document.xml → tracked changes and revision session IDs (rsid)

    total_time_mins = 0 → document was auto-generated (script-made forgery)
    unique_edit_sessions = how many times someone opened and edited the file
    """
    try:
        with zipfile.ZipFile(filepath) as z:
            names = z.namelist()

            if "docProps/app.xml" in names:
                app_xml = z.read("docProps/app.xml").decode("utf-8", errors="replace")

                def xml_val(tag, text):
                    m = re.search(rf"<(?:[^:>]+:)?{tag}[^>]*>(.*?)</", text, re.DOTALL)
                    return m.group(1).strip() if m else "N/A"

                result["app_properties"] = {
                    "application":     xml_val("Application", app_xml),
                    "app_version":     xml_val("AppVersion", app_xml),
                    "company":         xml_val("Company", app_xml),
                    "total_time_mins": xml_val("TotalTime", app_xml),
                    "pages":           xml_val("Pages", app_xml),
                    "words":           xml_val("Words", app_xml),
                    "paragraphs":      xml_val("Paragraphs", app_xml),
                    "doc_security":    xml_val("DocSecurity", app_xml),
                }

            if "word/document.xml" in names:
                doc_xml = z.read("word/document.xml").decode("utf-8", errors="replace")
                revision_marks = len(re.findall(r"<w:ins |<w:del ", doc_xml))
                result["revision_history"]["tracked_changes_count"] = revision_marks
                rsids = set(re.findall(r'w:rsid(?:R|RPr|Del|Default)?="([^"]+)"', doc_xml))
                result["revision_history"]["unique_edit_sessions"] = len(rsids)

    except Exception as e:
        result["app_properties"]["error"] = str(e)


def _apply_forensic_flags(result: dict):
    flags = result["forensic_flags"]
    cp    = result["core_properties"]
    app   = result["app_properties"]
    rev   = result["revision_history"]

    author  = cp.get("author", "N/A")
    last_by = cp.get("last_modified_by", "N/A")
    if author != "N/A" and last_by != "N/A" and author != last_by:
        flags.append({
            "severity": "MEDIUM", "code": "AUTHOR_MODIFIED_BY_MISMATCH",
            "detail": f"Original author '{author}' differs from last editor '{last_by}'"
        })

    try:
        if int(cp.get("revision", "0")) > 20:
            flags.append({
                "severity": "MEDIUM", "code": "HIGH_REVISION_COUNT",
                "detail": f"Revision number is {cp['revision']} — saved that many times"
            })
    except Exception:
        pass

    try:
        tt = int(app.get("total_time_mins", "-1"))
        if 0 <= tt <= 1:
            flags.append({
                "severity": "MEDIUM", "code": "ZERO_EDIT_TIME",
                "detail": f"Total editing time: {tt} min — document may be auto-generated"
            })
    except Exception:
        pass

    tc = rev.get("tracked_changes_count", 0)
    if tc > 0:
        flags.append({
            "severity": "MEDIUM", "code": "TRACKED_CHANGES_PRESENT",
            "detail": f"{tc} tracked change(s) — document has hidden insertions or deletions"
        })

    es = rev.get("unique_edit_sessions", 0)
    if es > 10:
        flags.append({
            "severity": "LOW", "code": "MANY_EDIT_SESSIONS",
            "detail": f"{es} unique edit session IDs (rsids) detected"
        })

    c_str = cp.get("created", "N/A")
    m_str = cp.get("modified", "N/A")
    if c_str != "N/A" and m_str != "N/A":
        try:
            if datetime.fromisoformat(c_str) > datetime.fromisoformat(m_str):
                flags.append({
                    "severity": "HIGH", "code": "DATE_INVERSION",
                    "detail": f"Created ({c_str}) is after Modified ({m_str}) — impossible"
                })
        except Exception:
            pass
