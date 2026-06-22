# PaperTrail AI — Metadata Forensics Layer

> **Cybersecurity component** of the PaperTrail AI document fraud detection system,
> built for the bank loan underwriting context (Canara Bank / PSU banks).

---

## 🎯 What This Does

This module is **Layer 1** of the PaperTrail AI system — the **Metadata Forensics Layer**.

It takes any loan document (PDF, Word, scanned image) and:
1. Extracts all hidden metadata (creation dates, author, software used, edit history)
2. Flags forensic anomalies using rule-based detection
3. Computes a **0–100 risk score** from the flags
4. Registers a **SHA-256 fingerprint** in a Merkle tree ledger for re-submission detection

---

## 📂 Project Structure

```
Suraksha/
├── run.py                    ← Single entry point (use this)
├── requirements.txt          ← Python dependencies
│
├── core/                     ← Cybersecurity forensics engine
│   ├── __init__.py           ← Unified extract_metadata() dispatcher
│   ├── utils.py              ← sha256_hash, parse_pdf_date, helpers
│   ├── pdf_forensics.py      ← PDF metadata extractor + flag rules
│   ├── docx_forensics.py     ← DOCX metadata extractor + flag rules
│   ├── image_forensics.py    ← JPG/PNG EXIF extractor + flag rules
│   ├── risk_scorer.py        ← 0–100 risk score calculator
│   └── hash_ledger.py        ← SHA-256 + Merkle tree integrity ledger
│
├── api/                      ← FastAPI REST layer (future)
│   └── routes.py
│
├── tests/                    ← Unit tests
│   └── test_extractor.py
│
└── reports/                  ← Auto-generated JSON forensic reports
```

---

## 🚀 Quick Start

### 1. Install system tools
```bash
sudo apt install poppler-utils     # pdfinfo command
sudo apt install libimage-exiftool-perl   # exiftool command
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Analyze a document
```bash
# Analyze a PDF
python run.py path/to/salary_slip.pdf

# Analyze a Word document
python run.py path/to/land_record.docx

# Analyze a scanned image
python run.py path/to/bank_statement.jpg

# Also output raw JSON
python run.py path/to/document.pdf --json

# Check hash ledger integrity
python run.py --verify-ledger
```

### 4. Run tests
```bash
python tests/test_extractor.py
```

---

## 🚩 Forensic Flags

| Code | Severity | Meaning |
|------|----------|---------|
| `DATE_INVERSION` | 🔴 HIGH | Creation date is after modification date — impossible |
| `SUSPICIOUS_PRODUCER` | 🔴 HIGH | PDF was re-saved by ilovepdf / Smallpdf / Foxit |
| `JAVASCRIPT_DETECTED` | 🔴 HIGH | Hidden JavaScript in a loan document |
| `EDITING_SOFTWARE_IN_EXIF` | 🔴 HIGH | Scanned image was opened in Photoshop/GIMP |
| `EXIF_DATE_INVERSION` | 🔴 HIGH | EXIF capture date is after file modification date |
| `HASH_MISMATCH_RESUBMISSION` | 🔴 HIGH | Same document re-submitted with different content |
| `MULTIPLE_EDITS` | 🟡 MEDIUM | PDF saved 3+ times incrementally |
| `ZERO_EDIT_TIME` | 🟡 MEDIUM | Word doc shows 0 min of editing (auto-generated) |
| `TRACKED_CHANGES_PRESENT` | 🟡 MEDIUM | Hidden insertions/deletions in Word doc |
| `AUTHOR_MODIFIED_BY_MISMATCH` | 🟡 MEDIUM | Different person last edited the document |
| `EDITING_TOOL_PRESENT` | 🟡 MEDIUM | PDF editor tool signatures in binary |
| `LOW_DPI` | 🟡 MEDIUM | Image DPI < 100 (screenshot, not genuine scan) |
| `NO_AUTHORSHIP_METADATA` | 🔵 LOW | Author/creator fields deliberately wiped |
| `GPS_METADATA_PRESENT` | 🔵 LOW | GPS coords in scanned doc (phone photograph) |
| `NO_DEVICE_SIGNATURE` | 🔵 LOW | No scanner make/model in EXIF |

---

## 🔒 SHA-256 + Merkle Tree Ledger

Every document gets fingerprinted on first submission.
If the same document (by filename) is re-submitted later with a changed hash,
a **CRITICAL** `HASH_MISMATCH` flag is raised instantly.

The ledger is stored at `reports/hash_ledger.json` and its integrity is
protected by a **Merkle root** — if the ledger file is externally tampered,
`--verify-ledger` will catch it.

---

## 🏗 Architecture (Your Part in the Bigger System)

```
Document Upload
      │
      ▼
┌─────────────────────────────┐
│  LAYER 1: METADATA FORENSICS│  ← THIS MODULE (your work)
│  (core/ package)            │
└─────────┬───────────────────┘
          │  risk_score + flags
          ▼
┌─────────────────────────────┐
│  LAYER 2: AI VISION + NLP   │  ← Teammates
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  LAYER 3: STAT OUTLIER ENG  │  ← Teammates
└─────────┬───────────────────┘
          │  combined risk signal
          ▼
┌─────────────────────────────┐
│  ANALYST DASHBOARD (React)  │  ← Frontend team
└─────────────────────────────┘
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `pypdf` | PDF metadata dictionary + XMP stream |
| `python-docx` | Word DOCX core properties |
| `Pillow` | Image format, DPI, JPEG quality |
| `exifread` | JPEG/TIFF EXIF data |
| `fastapi` + `uvicorn` | REST API (optional) |

System: `poppler-utils` (pdfinfo), `exiftool`
