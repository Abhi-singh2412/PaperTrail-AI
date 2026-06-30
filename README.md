<div align="center">

# 🛡️ DocShield

### AI-Powered Document Fraud Detection System

**Two independent detection engines. One verdict. Under 30 seconds.**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![spaCy](https://img.shields.io/badge/spaCy-NLP-09A3D5?style=for-the-badge&logo=spacy&logoColor=white)](https://spacy.io)
[![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)](https://supabase.com)
[![PyMuPDF](https://img.shields.io/badge/PyMuPDF-Forensics-FF6B35?style=for-the-badge)](https://pymupdf.readthedocs.io)

*Catch forged salary slips, fake certificates, and tampered financial documents — automatically, explainably, securely.*

</div>

---

## Working Video Solution
https://drive.google.com/file/d/1Y_hWUB2LMnAj5mMReRqKqtB318mCpiDZ/view?usp=sharing

## 🚩 The Problem

Every day, lenders, HR teams, and background-verification firms receive forged salary slips, fabricated Form 16s, and doctored bank statements. In India alone, document fraud costs the financial sector thousands of crores annually — and most of it goes unnoticed because verification is still done manually, if at all.

A PDF with a single font swap on a salary figure, a PAN that doesn't match its entity type, or a net pay that somehow exceeds gross income — these are easy to fake in Photoshop and easy to miss in a rushed inbox.

**DocShield makes them impossible to miss.**

| Attack Type | Example | Missed Manually? |
|---|---|---|
| Font swap on a single digit | ₹50,000 → ₹5,00,000 | Almost always |
| Entity-type PAN mismatch | Company PAN on individual payslip | Always |
| Net > Gross salary | Net pay ₹3.5L on Gross ₹2L | Frequently |
| Suspicious creator tool | Photoshop metadata on a bank statement | Always (nobody checks) |
| Future-dated document | Payslip dated 2035 | Occasionally |
| IFSC ↔ bank name clash | HDFC IFSC listed under SBI | Always |
| Resubmitted tampered PDF | Same filename, altered content, different hash | Always |

---

## ✨ What Makes This Different

Most document-verification tools either trust metadata blindly or run a black-box ML classifier that outputs a probability score with no explanation. DocShield does neither.

### 1. Dual-Engine Independence
Forgery leaves traces in two unrelated places: **the file itself** (metadata, structure, how it was produced) and **what it claims** (numbers that don't add up, identities that don't match). A single model trying to catch both is mediocre at each. DocShield splits them into two completely independent engines that each go deep on their domain, then combines their verdicts.

### 2. Explainability Over Probability
Every flag names exactly what is wrong — not *"87% fraud probability"* but:
```
ifsc_bank_mismatch: IFSC prefix 'HDFC' does not match stated bank 'Canara Bank' — confidence: 0.95
gross_salary_mismatch: sum of earnings (₹5,00,000) ≠ stated gross (₹2,00,000) — confidence: 0.98
```
Each flag carries a severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) and a confidence score. The report is an audit trail, not a verdict.

### 3. Zero-Trust Output
The fraud-detection report is itself sensitive data. Every annotated PDF is encrypted with a freshly generated random password **before** it ever leaves the server — so a direct download from cloud storage is useless without that password. Original and annotated PDFs live in separate private buckets, namespaced per user.

---

## ⚙️ How It Works

```
Upload PDF
    │
    ├──▶ Layer 1: Cyber / Forensics Engine  (/analyze/cyber)
    │         • SHA-256 hash + resubmission detection
    │         • PDF metadata forensics (author, creator tool, edit timing)
    │         • Embedded JS / attachment / encryption checks
    │         • Scan detection & per-page resolution analysis
    │
    └──▶ Layer 2: NLP / Content Engine  (/analyze/fraud)
              • spaCy NER entity extraction (money, dates, orgs, persons)
              • PAN structure + entity-type validation
              • IFSC ↔ bank name cross-check
              • Salary / CTC / TDS arithmetic reconciliation
              • Company verification against CIN whitelist
              • Font-consistency forensics across the document
              • Income-vs-profession plausibility check
                        │
                        ▼
         Risk Score + Credibility Score + Annotated, Flagged PDF
                        │
                        ▼
         Password-protected output → Supabase private storage (per user)
```

---

## 🔍 Detection Coverage

### Layer 1 — Cyber / Forensics

| Check | Flag Type | Severity |
|---|---|---|
| SHA-256 hash vs. previous submission | `resubmission_detected` | 🔴 CRITICAL |
| Cross-path duplicate detection | `duplicate_document` | 🟠 HIGH |
| Missing author metadata | `author_missing` | 🟡 MEDIUM |
| Modification within 60 min of creation | `rapid_modification` | 🟠 HIGH |
| Creator tool is Photoshop / GIMP / Canva / Inkscape | `suspicious_creator_tool` | 🟠 HIGH |
| PDF is encrypted / password-protected at source | `pdf_encrypted` | 🟠 HIGH |
| Embedded JavaScript detected | `embedded_javascript` | 🔴 CRITICAL |
| Embedded file attachments | `embedded_attachments` | 🟠 HIGH |
| Page count below minimum for document type | `suspicious_page_count` | 🟡 MEDIUM |
| File size under 5 KB | `suspicious_file_size` | 🟡 MEDIUM |
| All pages are image-based (no selectable text) | `fully_scanned_document` | 🟡 MEDIUM |
| Mix of native and scanned pages | `mixed_document` | 🟡 MEDIUM |
| Per-page DPI below 150 | `low_resolution_scan` | 🟠 HIGH |
| DPI varies >100 across pages (spliced scans) | `inconsistent_resolution` | 🟠 HIGH |

### Layer 2 — NLP / Content

| Check | Flag Type | Severity |
|---|---|---|
| Gross salary ≠ sum of earnings components | `gross_salary_mismatch` | 🔴 CRITICAL |
| Net salary > Gross salary | `net_exceeds_gross` | 🔴 CRITICAL |
| Total deductions inconsistent | `deductions_mismatch` | 🟠 HIGH |
| Annual TDS ≠ Monthly TDS × 12 | `annual_tds_mismatch` | 🟠 HIGH |
| Annual CTC vs Gross × 12 deviation > 20% | `ctc_mismatch` | 🟠 HIGH |
| PAN fails regex pattern | `invalid_pan_format` | 🔴 CRITICAL |
| PAN entity type wrong for document context | `pan_entity_type_mismatch` | 🟠 HIGH |
| Multiple different PAN numbers on same document | `multiple_pan_numbers` | 🟠 HIGH |
| IFSC prefix doesn't match stated bank name | `ifsc_bank_mismatch` | 🔴 CRITICAL |
| Multiple conflicting IFSC codes on one document | `multiple_ifsc_codes` | 🟡 MEDIUM |
| Company name not in CIN whitelist | `unverified_company` | 🟡 MEDIUM |
| CIN format invalid | `invalid_cin_format` | 🟠 HIGH |
| Date is in the future | `future_date` | 🟠 HIGH |
| Impossible calendar date (e.g. 32/13/2099) | `invalid_date` | 🔴 CRITICAL |
| Salary outside plausible range for stated profession | `salary_out_of_range` | 🟠 HIGH |
| Font inconsistency detected across the document | `font_inconsistency` | 🟡 MEDIUM |

---

## 🏗️ Architecture

### Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | Flask (Python) | Lightweight, synchronous — ideal for sequential PDF processing |
| Cyber engine | PyMuPDF (`fitz`) | Low-level PDF struct access: metadata, encryption flags, embedded objects, per-page DPI |
| NLP engine | spaCy `en_core_web_sm` | Fast rule-augmented NER — MONEY, DATE, ORG, PERSON — no LLM API call needed |
| PDF annotation | PyMuPDF | Writes color-coded flag boxes directly onto a copy of the source PDF |
| PDF encryption | `pypdf` PdfWriter | Encrypts annotated output before it ever leaves the server |
| Auth | PBKDF2-SHA256, 100k iterations | Per-user salt; plaintext never stored or logged |
| Persistence | Supabase (Postgres) | `users` + `documents` tables; zero-config managed DB |
| File storage | Supabase Storage | Private buckets; per-user namespacing; secret-key-only access |
| Frontend | Vanilla HTML/CSS/JS | Zero build step; PDF.js for in-browser rendering; dark security-console UI |

### Risk Scoring

Each engine scores independently using a weighted severity model:

| Score Range | Verdict | Meaning |
|---|---|---|
| ≥ 0.70 | 🔴 CRITICAL | Clear signs of forgery — auto-reject recommended |
| 0.50 – 0.69 | 🟠 HIGH | Multiple serious issues — mandatory human review |
| 0.25 – 0.49 | 🟡 MEDIUM | Inconsistencies detected — verify before proceeding |
| < 0.25 | 🟢 LOW | Minor or no issues — document appears legitimate |

Flag weights: `CRITICAL = 0.5` · `HIGH = 0.25` · `MEDIUM = 0.1` · `LOW = 0.05`

---

## 📁 Project Structure

```
PaperTrail-AI/
├── start.py                              # Entry point — dependency checks + launch
├── app.py                                # Flask server: auth, routes, Supabase wiring
├── config.py                             # Tunable thresholds, whitelists, IFSC/bank maps
├── cyber_detector_module.py              # Layer 1: file/metadata forensics engine
├── cyber_detector.py                     # Original cyber detector (unchanged)
├── document_fraud_detector_enhanced.py   # Layer 2: NLP content analysis + PDF annotation
├── fraud_detector_module.py              # Thin wrapper exposing Layer 2 to Flask
├── hash_store.json                       # SHA-256 resubmission memory (auto-managed)
├── requirements.txt
├── .env                                  # Not committed — your secrets go here
├── supabase_setup.sql                    # One-time DB schema (run once in Supabase SQL Editor)
├── uploads/                              # Temp storage for incoming PDFs
├── outputs/                              # Annotated + encrypted PDF outputs
└── static/
    ├── landing.html                      # Login / signup UI
    └── index.html                        # Analysis console + PDF.js viewer
```

### File Responsibilities

| File | Key Functions |
|---|---|
| `start.py` | Checks all imports, auto-downloads spaCy model if missing, launches Flask on `:5000` |
| `app.py` | `/signup` `/login` `/logout` `/me` `/upload` `/analyze/cyber` `/analyze/fraud` `/download` `/report` |
| `cyber_detector_module.py` | `check_resubmission()` `check_metadata()` `check_file_anomalies()` `check_scanned_document()` `run_cyber_analysis()` |
| `document_fraud_detector_enhanced.py` | spaCy NER pipeline, PAN/IFSC/CIN validators, salary arithmetic, font forensics, PyMuPDF annotation |
| `fraud_detector_module.py` | `run_fraud_analysis()` — adapter; moves annotated PDF to output folder, returns serializable JSON |
| `config.py` | `PROFESSION_SALARY_RANGES` `COMPANY_WHITELIST` `BANK_IFSC_MAP` `RISK_WEIGHTS` `SEVERITY_LEVELS` — all tunable without touching engine code |
| `hash_store.json` | Per-path SHA-256 store; detects tampered resubmissions and cross-path duplicates across sessions |

---

## 🔐 Security Design

| Area | Implementation |
|---|---|
| Password storage | PBKDF2-SHA256, 100,000 iterations, unique random salt per user. Plaintext never stored or logged. |
| Session management | Server-side Flask sessions via signed cookies. Fixed `FLASK_SECRET_KEY` keeps sessions valid across restarts. |
| Output encryption | Every annotated PDF encrypted with a freshly generated random password before upload to storage. Password shown once; stored in `documents` table for retrieval. |
| File storage | Original + annotated PDFs in separate private Supabase Storage buckets; inaccessible without the server's secret key. Per-user folder namespacing. |
| CORS | Locked to explicit `ALLOWED_ORIGIN` (not `*`) — required for credentialed cookie-carrying requests. |
| Path traversal | `/download` sanitizes filename with `os.path.basename()` before serving from the outputs folder. |
| Auth endpoints | `hmac.compare_digest()` for constant-time password comparison. All `/upload` and `/analyze` routes return `401` if session is absent. |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- A free [Supabase](https://supabase.com) project

### 1. Install dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Configure environment

Create a `.env` file in the project root:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SECRET_KEY=sb_secret_xxxxxxxxxxxx
FLASK_SECRET_KEY=<a long random string — keep it the same across restarts>
```

> **Getting your Supabase secret key:** Dashboard → Settings → API Keys → use the `secret` key (not the `anon` / publishable key). The secret key bypasses Row Level Security so the server can read/write the users table.

### 3. One-time Supabase setup

In the Supabase Dashboard → SQL Editor, paste and run `supabase_setup.sql`. This creates the `users` and `documents` tables.

### 4. Launch

```bash
python start.py
```

Open **http://localhost:5000** → sign up → log in → drop in a PDF.

---

## 🌐 API Reference

| Method | Endpoint | Auth? | Description |
|---|---|---|---|
| `GET` | `/` | No | Serves `landing.html` (login / signup) |
| `POST` | `/signup` | No | Create account — `{email, password}` |
| `POST` | `/login` | No | Authenticate → sets session cookie |
| `POST` | `/logout` | Yes | Clears session cookie |
| `GET` | `/me` | Yes | Returns `{email}` of logged-in user or `401` |
| `POST` | `/upload` | Yes | Upload PDF → `{filename, size_kb, original_name}` |
| `POST` | `/analyze/cyber` | Yes | Run Layer 1 on `{filename}` → cyber result JSON |
| `POST` | `/analyze/fraud` | Yes | Run Layer 2 on `{filename}` → fraud result JSON + annotated PDF |
| `GET` | `/download/<filename>` | Yes | Stream the annotated (encrypted) PDF |
| `POST` | `/report` | Yes | Generate + download full JSON report |

---

## ⚙️ Configuration

All thresholds live in `config.py` — tunable without touching engine code:

```python
# Profession salary ranges (monthly, INR)
PROFESSION_SALARY_RANGES = {
    "peon": (5000, 20000),
    "software engineer": (50000, 300000),
    "manager": (60000, 250000),
    # Add your own:
    "your_role": (min_salary, max_salary),
}

# Company → CIN whitelist
COMPANY_WHITELIST = {
    "HDFC Bank Ltd": "L65920MH1994PLC080618",
    "Infosys Ltd": "L85110KA1981PLC013115",
    # Add your own:
    "Your Company": "CIN_CODE_HERE",
}

# Bank → IFSC prefix map
BANK_IFSC_MAP = {
    "canara bank": "CNRB",
    "hdfc bank": "HDFC",
    # Add your own:
    "your bank": "IFSC_PREFIX",
}
```

---

## 🧪 Test Documents

The repo includes two deliberately crafted sample PDFs with **16 planted fraud signals**:

| # | Signal |
|---|---|
| 1 | Future date (2035) |
| 2 | Fake company spelling ("Canaraa Bank Ltd") |
| 3 | Invalid CIN format |
| 4 | Unrealistic salary for a Peon (₹3.5L/month) |
| 5 | Earnings components don't sum to stated Gross |
| 6 | Net Salary greater than Gross Salary |
| 7 | Total Deductions inconsistent |
| 8 | Annual CTC mismatch |
| 9 | Annual TDS ≠ Monthly TDS × 12 |
| 10 | IFSC prefix doesn't match stated bank |
| 11 | Multiple conflicting IFSC codes |
| 12 | Invalid PAN entity type |
| 13 | Duplicate / multiple PAN numbers |
| 14 | Invalid bank account number format |
| 15 | OCR-style amount error (₹1,2A,000) |
| 16 | Impossible calendar date (32/13/2099) |

DocShield flags all 16. `sample_flagged.pdf` is the annotated output with color-coded boxes.

---

## 🎯 Real-World Applicability

| User | Use Case | Value |
|---|---|---|
| NBFC / Lending companies | Income verification before loan disbursal | Catch salary fraud before funds are released |
| HR / Background verification firms | Payslip and certificate verification | Eliminate manual review for routine checks |
| Banks | KYC document forensics at account opening | Automated first pass before compliance review |
| Insurance companies | Claim document verification | Detect fabricated medical bills or salary proofs |
| Government portals | Subsidy / scholarship document screening | Fair, consistent, automated screening at scale |

### Scalability Path

- **`config.py` is already structured** for per-organization whitelists — populate the dicts, restart, done.
- **The `documents` table** stores every scan with full JSON results — a history/audit view is one query away.
- **Batch upload** is architecturally straightforward: loop `/upload` + `/analyze/cyber` + `/analyze/fraud`.
- **New document types** (bank statements, ITRs, property valuations) add keyword sets to `config.py` and new validators to the engine — no core rewrites.
- **New fraud patterns** are modular functions — the engine doesn't need to change to add a new check.

---

## 🔮 Roadmap

- [ ] Per-organization whitelists exposed in the UI (config.py already supports this)
- [ ] Audit trail / history view backed by the `documents` table
- [ ] Batch upload for bulk verification workflows
- [ ] Webhook integration — POST results to a lender's CRM on completion
- [ ] Dockerized deployment — single `docker-compose up`
- [ ] Multi-language NER — Hindi, Tamil, Telugu document text
- [ ] Admin dashboard — aggregate risk metrics across users

---

## 📦 Requirements

```
flask>=2.3.0
flask-cors>=4.0.0
pymupdf>=1.23.0
spacy>=3.7.0
python-dateutil>=2.8.0
supabase
pypdf
```

---

<div align="center">

**DocShield** — catch what a skim-read misses.

*Built for hackathon submission · Two engines · One verdict · Zero guesswork*

</div>
