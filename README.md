# DocShield — Document Fraud Detection System

## Quick Start

1. Install dependencies:
   ```
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

2. Run:
   ```
   python start.py
   ```

3. Open http://localhost:5000 in your browser

## Files

| File | Purpose |
|------|---------|
| `start.py` | **Launch this file** — checks deps and starts the server |
| `app.py` | Flask web server + API routes |
| `static/index.html` | Frontend UI (HTML/CSS/JS) |
| `cyber_detector_module.py` | Cyber integrity checks (hash, metadata, file anomalies, scan detection) |
| `fraud_detector_module.py` | Content fraud analysis (delegates to document_fraud_detector_enhanced.py) |
| `cyber_detector.py` | Original cyber detector (unchanged) |
| `document_fraud_detector_enhanced.py` | Original fraud detector (unchanged) |

## How it works

1. Upload a PDF via the browser
2. The UI runs two scans in parallel:
   - **Cyber Check**: hash integrity, metadata anomalies, embedded JS/attachments, scan detection
   - **Content Fraud**: financial consistency, PAN/IFSC validation, date checks, company verification
3. Download the annotated PDF (flags highlighted in the PDF) or the full JSON report
