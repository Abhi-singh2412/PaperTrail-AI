import os
import json
import subprocess
from datetime import datetime

from .utils import sha256_hash, safe_str


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

    _read_basic_properties(filepath, result)
    _read_exif_data(filepath, result)
    _run_exiftool(filepath, result)
    _apply_forensic_flags(result)

    return result


def _read_basic_properties(filepath: str, result: dict):
    """
    Use Pillow to read basic image properties.
    JPEG quality < 60 can mask splicing artifacts (important fraud signal).
    """
    try:
        from PIL import Image
        img = Image.open(filepath)
        result["basic_properties"] = {
            "format":    img.format,
            "mode":      img.mode,
            "width_px":  img.size[0],
            "height_px": img.size[1],
            "dpi":       str(img.info.get("dpi", "N/A")),
            "has_icc":   "icc_profile" in img.info,
        }

        if img.format == "JPEG":
            try:
                qtables = img.quantization
                avg_q = sum(qtables[0]) / len(qtables[0])
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
    except ImportError:
        result["basic_properties"]["error"] = "Pillow not installed (pip install Pillow)"
    except Exception as e:
        result["basic_properties"]["error"] = str(e)


def _read_exif_data(filepath: str, result: dict):
    """
    Use exifread to extract EXIF metadata from JPEG/TIFF images.
    Key fields: camera make/model, GPS coordinates, software used, timestamps.

    Forensic insight: A genuine scanned document always has scanner model info.
    A forged image (screenshot → edited → saved) typically has no make/model.
    """
    try:
        import exifread
        with open(filepath, "rb") as f:
            tags = exifread.process_file(f, stop_tag="UNDEF", details=False)

        def tag(name):
            return str(tags.get(name, "N/A"))

        result["exif_data"] = {
            "make":               tag("Image Make"),
            "model":              tag("Image Model"),
            "software":           tag("Image Software"),
            "datetime_original":  tag("EXIF DateTimeOriginal"),
            "datetime_digitized": tag("EXIF DateTimeDigitized"),
            "datetime_modified":  tag("Image DateTime"),
            "gps_latitude":       tag("GPS GPSLatitude"),
            "gps_longitude":      tag("GPS GPSLongitude"),
            "gps_altitude":       tag("GPS GPSAltitude"),
            "user_comment":       tag("EXIF UserComment"),
            "document_name":      tag("Image DocumentName"),
            "image_description":  tag("Image ImageDescription"),
            "copyright":          tag("Image Copyright"),
            "artist":             tag("Image Artist"),
            "x_resolution":       tag("Image XResolution"),
            "y_resolution":       tag("Image YResolution"),
            "color_space":        tag("EXIF ColorSpace"),
            "flash":              tag("EXIF Flash"),
            "exposure_time":      tag("EXIF ExposureTime"),
            "f_number":           tag("EXIF FNumber"),
            "iso_speed":          tag("EXIF ISOSpeedRatings"),
        }
    except ImportError:
        result["exif_data"]["error"] = "exifread not installed (pip install exifread)"
    except Exception as e:
        result["exif_data"]["error"] = str(e)


def _run_exiftool(filepath: str, result: dict):
    """
    Cross-validate with exiftool (system tool) for richer metadata.
    Install: sudo apt install exiftool  (or: sudo apt install libimage-exiftool-perl)
    """
    keys_of_interest = [
        "FileModifyDate", "FileCreateDate", "CreateDate",
        "ModifyDate", "MetadataDate", "HistoryWhen",
        "OriginalDocumentID", "DocumentID", "InstanceID",
        "CreatorTool", "Producer", "PDFVersion",
        "XMPToolkit", "HistoryAction", "HistorySoftwareAgent"
    ]
    try:
        out = subprocess.check_output(
            ["exiftool", "-json", "-a", "-u", filepath],
            stderr=subprocess.DEVNULL, text=True
        )
        etdata = json.loads(out)[0] if out.strip() else {}
        result["exiftool_extras"] = {k: str(etdata[k]) for k in keys_of_interest if k in etdata}
    except FileNotFoundError:
        result["exiftool_extras"] = {"error": "exiftool not installed (sudo apt install exiftool)"}
    except Exception as e:
        result["exiftool_extras"] = {"error": str(e)}


def _apply_forensic_flags(result: dict):
    flags = result["forensic_flags"]
    exif  = result["exif_data"]
    basic = result["basic_properties"]
    et    = result.get("exiftool_extras", {})

    # --- Rule 1: Editing software found in EXIF (Photoshop, GIMP, etc.) ---
    suspicious_software = [
        "Photoshop", "GIMP", "Pixelmator", "Affinity",
        "Canva", "Paint.NET", "Snapseed", "LightRoom", "Acrobat"
    ]
    sw = exif.get("software", "N/A") + et.get("CreatorTool", "")
    found_sw = [s for s in suspicious_software if s.lower() in sw.lower()]
    if found_sw:
        flags.append({
            "severity": "HIGH", "code": "EDITING_SOFTWARE_IN_EXIF",
            "detail": f"Image edited with: {found_sw} — not consistent with a genuine scan"
        })

    # --- Rule 2: GPS data in a scanned document ---
    # Scanned documents don't have GPS. If GPS is present, the document was
    # photographed with a phone — possible physical forgery.
    if exif.get("gps_latitude", "N/A") != "N/A":
        flags.append({
            "severity": "LOW", "code": "GPS_METADATA_PRESENT",
            "detail": "GPS coordinates embedded — document was photographed with a mobile device"
        })

    # --- Rule 3: Original capture date AFTER file modification date ---
    dt_orig  = exif.get("datetime_original", "N/A")
    dt_modif = exif.get("datetime_modified", "N/A")
    if dt_orig != "N/A" and dt_modif != "N/A" and dt_orig != dt_modif:
        try:
            d1 = datetime.strptime(dt_orig[:19],  "%Y:%m:%d %H:%M:%S")
            d2 = datetime.strptime(dt_modif[:19], "%Y:%m:%d %H:%M:%S")
            if d1 > d2:
                flags.append({
                    "severity": "HIGH", "code": "EXIF_DATE_INVERSION",
                    "detail": f"Original capture ({dt_orig}) is AFTER file modification ({dt_modif}) — EXIF was tampered"
                })
        except Exception:
            pass

    # --- Rule 4: DPI too low for a genuine document scan ---
    # Bank docs scanned at 200–300 DPI. < 100 DPI = screenshot or camera photo.
    dpi_raw = basic.get("dpi", "N/A")
    try:
        dpi_val = float(str(dpi_raw).strip("()'\" ").split(",")[0])
        if dpi_val < 100:
            flags.append({
                "severity": "MEDIUM", "code": "LOW_DPI",
                "detail": f"DPI = {dpi_val} — too low for a genuine document scan (expected 200–300)"
            })
    except Exception:
        pass

    # --- Rule 5: No make/model (genuine scans always have scanner model) ---
    if exif.get("make", "N/A") == "N/A" and exif.get("model", "N/A") == "N/A":
        flags.append({
            "severity": "LOW", "code": "NO_DEVICE_SIGNATURE",
            "detail": "No camera/scanner make or model in EXIF — metadata may have been stripped"
        })
