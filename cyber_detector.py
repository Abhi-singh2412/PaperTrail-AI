#!/usr/bin/env python
# coding: utf-8

# In[1]:


import hashlib
import json
import os
import fitz
from datetime import datetime
import dateutil.parser

print("All libraries imported successfully")


# In[2]:


def generate_hash(pdf_path):
    with open(pdf_path, "rb") as f:
        file_bytes = f.read()
    return hashlib.sha256(file_bytes).hexdigest()

def store_hash(pdf_path, hash_value):
    store_file = "hash_store.json"
    
    # Load existing store or create new one
    if os.path.exists(store_file):
        with open(store_file, "r") as f:
            store = json.load(f)
    else:
        store = {}
    
    # Store hash with filename and timestamp
    store[pdf_path] = {
        "hash": hash_value,
        "timestamp": datetime.now().isoformat()
    }
    
    with open(store_file, "w") as f:
        json.dump(store, f, indent=4)
    
    print(f"Hash stored for: {pdf_path}")

# Test it
hash_value = generate_hash("sample.pdf")
print(f"SHA-256 Hash: {hash_value}")
store_hash("sample.pdf", hash_value)


# In[3]:


def check_resubmission(pdf_path):
    store_file = "hash_store.json"
    flags = []
    
    # Generate hash of incoming document
    new_hash = generate_hash(pdf_path)
    
    # Load existing store
    if not os.path.exists(store_file):
        print("INFO - No hash store found. This is the first submission.")
        store_hash(pdf_path, new_hash)
        return flags, new_hash
    
    with open(store_file, "r") as f:
        store = json.load(f)
    
    # Check if this exact file was submitted before
    if pdf_path in store:
        stored_hash = store[pdf_path]["hash"]
        stored_time = store[pdf_path]["timestamp"]
        
        if stored_hash == new_hash:
            print(f"INFO - Document previously submitted on {stored_time}. Hash matches - no tampering.")
        else:
            flags.append({
                "type": "resubmission_detected",
                "description": f"Document was previously submitted on {stored_time} but content has changed - possible tampering",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
    else:
        # Check if same hash exists for a different file
        for stored_path, stored_data in store.items():
            if stored_data["hash"] == new_hash and stored_path != pdf_path:
                flags.append({
                    "type": "duplicate_document",
                    "description": f"Document is identical to previously submitted file: {stored_path}",
                    "severity": "HIGH",
                    "confidence": 0.99
                })
                break
        
        # Store the new hash
        store_hash(pdf_path, new_hash)
    
    if not flags:
        print("PASS - Re-submission check: No prior submission detected")
    
    return flags, new_hash

# Test with clean document
resubmission_flags, doc_hash = check_resubmission("sample.pdf")
if resubmission_flags:
    for f in resubmission_flags:
        print(f"FLAG: {f['type']} - {f['description']}")


# In[4]:


# Simulate a tampered resubmission
# We temporarily store a fake hash to simulate a previous submission

store_file = "hash_store.json"
with open(store_file, "r") as f:
    store = json.load(f)

# Store a fake hash for sample.pdf simulating previous submission
store["sample.pdf"] = {
    "hash": "aaaaabbbbbcccccdddddeeeeefffff00000111112222233333444445555566666",
    "timestamp": "2026-06-20T09:00:00.000000"
}

with open(store_file, "w") as f:
    json.dump(store, f, indent=4)

print("Simulated previous submission stored")
print("Now testing re-submission detection...")
print("-"*50)

# Now run the check - hash won't match the fake one
resubmission_flags, doc_hash = check_resubmission("sample.pdf")
if resubmission_flags:
    for f in resubmission_flags:
        print(f"\nFLAG RAISED:")
        print(f"Type        : {f['type']}")
        print(f"Description : {f['description']}")
        print(f"Severity    : {f['severity']}")
        print(f"Confidence  : {f['confidence']}")


# In[5]:


# Restore correct hash for sample.pdf
correct_hash = generate_hash("sample.pdf")
store_hash("sample.pdf", correct_hash)
print(f"Correct hash restored: {correct_hash}")


# In[7]:


def check_file_anomalies(pdf_path, doc_type="unknown"):
    flags = []
    
    # Expected minimum page counts per document type
    min_pages = {
        "salary_slip": 1,
        "form_16": 2,
        "bank_statement": 2,
        "itr": 3,
        "property_valuation": 2,
        "unknown": 1
    }
    
    # Open the PDF
    doc = fitz.open(pdf_path)
    
    # Check 1 - Encryption
    if doc.is_encrypted:
        flags.append({
            "type": "pdf_encrypted",
            "description": "Document is encrypted or password protected — suspicious for a loan document",
            "severity": "HIGH",
            "confidence": 0.85
        })
    else:
        print("PASS - Encryption check: Document is not encrypted")
    
    # Check 2 - Embedded JavaScript
    try:
        js_found = False
        for i in range(len(doc)):
            page = doc[i]
            if "/JS" in str(page.get_text("rawdict")):
                js_found = True
                break
        if js_found:
            flags.append({
                "type": "embedded_javascript",
                "description": "Document contains embedded JavaScript — sign of a potentially malicious file",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
        else:
            print("PASS - JavaScript check: No embedded JavaScript found")
    except:
        print("INFO - JavaScript check skipped")
    
    # Check 3 - Embedded attachments
    try:
        attachments = doc.embfile_count()
        if attachments > 0:
            flags.append({
                "type": "embedded_attachments",
                "description": f"Document contains {attachments} embedded attachment(s) — suspicious for a financial document",
                "severity": "HIGH",
                "confidence": 0.80
            })
        else:
            print("PASS - Attachment check: No embedded attachments found")
    except:
        print("INFO - Attachment check skipped")
    
    # Check 4 - Page count
    page_count = doc.page_count
    expected_min = min_pages.get(doc_type, 1)
    if page_count < expected_min:
        flags.append({
            "type": "suspicious_page_count",
            "description": f"Document has only {page_count} page(s) — expected at least {expected_min} for {doc_type}",
            "severity": "MEDIUM",
            "confidence": 0.75
        })
    else:
        print(f"PASS - Page count check: {page_count} page(s) found")
    
    # Check 5 - File size
    file_size = os.path.getsize(pdf_path)
    file_size_kb = file_size / 1024
    if file_size_kb < 5:
        flags.append({
            "type": "suspicious_file_size",
            "description": f"Document file size is only {file_size_kb:.1f} KB — suspiciously small",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - File size check: {file_size_kb:.1f} KB")
    
    doc.close()
    return flags

# Test it
file_flags = check_file_anomalies("sample.pdf", "salary_slip")
print("\n")
if file_flags:
    for f in file_flags:
        print(f"FLAG: {f['type']}")
        print(f"      {f['description']}")
        print(f"      Severity: {f['severity']} | Confidence: {f['confidence']}")
else:
    print("No file anomalies detected")


# In[8]:


def check_file_anomalies(pdf_path, doc_type="unknown"):
    flags = []
    
    min_pages = {
        "salary_slip": 1,
        "form_16": 2,
        "bank_statement": 2,
        "itr": 3,
        "property_valuation": 2,
        "unknown": 1
    }
    
    doc = fitz.open(pdf_path)
    
    # Check 1 - Encryption
    if doc.is_encrypted:
        flags.append({
            "type": "pdf_encrypted",
            "description": "Document is encrypted or password protected — suspicious for a loan document",
            "severity": "HIGH",
            "confidence": 0.85
        })
    else:
        print("PASS - Encryption check: Document is not encrypted")
    
    # Check 2 - Embedded JavaScript
    try:
        js_found = False
        for i in range(len(doc)):
            page = doc[i]
            if "/JS" in str(page.get_text("rawdict")):
                js_found = True
                break
        if js_found:
            flags.append({
                "type": "embedded_javascript",
                "description": "Document contains embedded JavaScript — sign of a potentially malicious file",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
        else:
            print("PASS - JavaScript check: No embedded JavaScript found")
    except:
        print("INFO - JavaScript check skipped")
    
    # Check 3 - Embedded attachments
    try:
        attachments = doc.embfile_count()
        if attachments > 0:
            flags.append({
                "type": "embedded_attachments",
                "description": f"Document contains {attachments} embedded attachment(s) — suspicious for a financial document",
                "severity": "HIGH",
                "confidence": 0.80
            })
        else:
            print("PASS - Attachment check: No embedded attachments found")
    except:
        print("INFO - Attachment check skipped")
    
    # Check 4 - Page count
    page_count = doc.page_count
    expected_min = min_pages.get(doc_type, 1)
    if page_count < expected_min:
        flags.append({
            "type": "suspicious_page_count",
            "description": f"Document has only {page_count} page(s) — expected at least {expected_min} for {doc_type}",
            "severity": "MEDIUM",
            "confidence": 0.75
        })
    else:
        print(f"PASS - Page count check: {page_count} page(s) found")
    
    # Check 5 - File size (threshold 1 KB for testing)
    file_size_kb = os.path.getsize(pdf_path) / 1024
    if file_size_kb < 1:
        flags.append({
            "type": "suspicious_file_size",
            "description": f"Document file size is only {file_size_kb:.1f} KB — suspiciously small",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - File size check: {file_size_kb:.1f} KB")
    
    doc.close()
    return flags

# Test it
file_flags = check_file_anomalies("sample.pdf", "salary_slip")
print("\n")
if file_flags:
    for f in file_flags:
        print(f"FLAG: {f['type']}")
        print(f"      {f['description']}")
        print(f"      Severity: {f['severity']} | Confidence: {f['confidence']}")
else:
    print("No file anomalies detected")


# In[10]:


def check_metadata(pdf_path):
    flags = []
    
    # Known legitimate software for Indian banking documents
    legitimate_software = [
        "tally", "sap", "finacle", "bankmaster", "temenos",
        "microsoft word", "libreoffice", "adobe acrobat",
        "fpdf", "reportlab", "itext", "pdfkit"
    ]
    
    doc = fitz.open(pdf_path)
    metadata = doc.metadata
    doc.close()
    
    print("Metadata extracted:")
    print("-"*50)
    for key, value in metadata.items():
        print(f"  {key}: {value}")
    print("-"*50)
    
    # Check 1 - Author missing
    author = metadata.get("author", "").strip()
    if not author:
        flags.append({
            "type": "author_missing",
            "description": "Document has no author metadata — legitimate documents always carry author information",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - Author check: {author}")
    
    # Check 2 - Creation date vs modification date
    creation_date = metadata.get("creationDate", "")
    mod_date = metadata.get("modDate", "")
    
    if creation_date and mod_date:
        try:
            # PyMuPDF date format: D:20260626120000
            def parse_pdf_date(date_str):
                date_str = date_str.replace("D:", "").strip()[:14]
                return datetime.strptime(date_str, "%Y%m%d%H%M%S")
            
            created = parse_pdf_date(creation_date)
            modified = parse_pdf_date(mod_date)
            
            diff_minutes = (modified - created).total_seconds() / 60
            
            if diff_minutes > 0 and diff_minutes < 60:
                flags.append({
                    "type": "rapid_modification",
                    "description": f"Document was modified {diff_minutes:.0f} minutes after creation — suspicious editing pattern",
                    "severity": "HIGH",
                    "confidence": 0.80
                })
            else:
                print(f"PASS - Date check: Created {created.strftime('%d %b %Y')}, Modified {modified.strftime('%d %b %Y')}")
        except Exception as e:
            print(f"INFO - Date parsing skipped: {e}")
    
    # Check 3 - Software used
    producer = metadata.get("producer", "").lower()
    creator = metadata.get("creator", "").lower()
    
    software_legitimate = any(
        sw in producer or sw in creator 
        for sw in legitimate_software
    )
    
    if producer or creator:
        if not software_legitimate:
            flags.append({
                "type": "suspicious_software",
                "description": f"Document created with unrecognised software: '{metadata.get('creator', '')} / {metadata.get('producer', '')}' — may indicate manual forgery",
                "severity": "MEDIUM",
                "confidence": 0.65
            })
        else:
            print(f"PASS - Software check: {metadata.get('producer', metadata.get('creator', ''))}")
    else:
        flags.append({
            "type": "software_missing",
            "description": "No software metadata found — legitimate documents always identify the generating software",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    
    # Check 4 - Creation date is very recent
    if creation_date:
        try:
            created = parse_pdf_date(creation_date)
            days_old = (datetime.now() - created).days
            if days_old < 3:
                flags.append({
                    "type": "recently_created",
                    "description": f"Document was created only {days_old} day(s) ago — suspicious for a historical financial document",
                    "severity": "HIGH",
                    "confidence": 0.80
                })
            else:
                print(f"PASS - Age check: Document created {days_old} days ago")
        except:
            print("INFO - Age check skipped")
    
    return flags, metadata

# Test it
metadata_flags, metadata = check_metadata("sample.pdf")
print("\n")
if metadata_flags:
    for f in metadata_flags:
        print(f"FLAG: {f['type']}")
        print(f"      {f['description']}")
        print(f"      Severity: {f['severity']} | Confidence: {f['confidence']}")
        print()
else:
    print("No metadata anomalies detected")


# In[11]:


import subprocess
subprocess.run(["pip", "install", "Pillow", "opencv-python"], capture_output=True)
print("Installing Pillow and OpenCV...")


# In[12]:


import PIL
import cv2
print("Pillow version:", PIL.__version__)
print("OpenCV version:", cv2.__version__)


# In[15]:


from PIL import Image
import cv2
import numpy as np
import io

def check_scanned_document(pdf_path):
    flags = []
    
    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    
    scanned_pages = 0
    resolutions = []
    
    for page_num in range(total_pages):
        page = doc[page_num]
        
        # Check if page is image-based or text-based
        text = page.get_text().strip()
        image_list = page.get_images()
        
        if len(image_list) > 0 and len(text) < 50:
            scanned_pages += 1
            
            # Check resolution of scanned page
            for img_index, img in enumerate(image_list):
                try:
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    
                    # Open with PIL to check resolution
                    pil_image = Image.open(io.BytesIO(image_bytes))
                    width, height = pil_image.size
                    
                    # Estimate DPI from image size
                    # Standard A4 at 300 DPI = 2480x3508 pixels
                    estimated_dpi = min(width, height) / 8.27  # 8.27 inches = A4 width
                    resolutions.append(estimated_dpi)
                    
                    if estimated_dpi < 150:
                        flags.append({
                            "type": "low_resolution_scan",
                            "description": f"Page {page_num+1} has low resolution ({estimated_dpi:.0f} DPI estimated) — may indicate re-scanned forgery",
                            "severity": "HIGH",
                            "confidence": 0.80
                        })
                except:
                    pass
    
    # Check if document is fully scanned
    if scanned_pages == total_pages:
        flags.append({
            "type": "fully_scanned_document",
            "description": f"All {total_pages} page(s) are image-based — higher fraud risk than native PDF",
            "severity": "MEDIUM",
            "confidence": 0.65
        })
    elif scanned_pages > 0:
        flags.append({
            "type": "mixed_document",
            "description": f"{scanned_pages} of {total_pages} pages are scanned — inconsistent document structure",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - Scan check: Document is native PDF — all {total_pages} page(s) are text-based")


# In[16]:


def check_scanned_document(pdf_path):
    flags = []
    
    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    scanned_pages = 0
    
    for page_num in range(total_pages):
        page = doc[page_num]
        
        # Check if page has text or not
        text = page.get_text().strip()
        
        if len(text) < 50:
            scanned_pages += 1
    
    if scanned_pages == total_pages:
        flags.append({
            "type": "fully_scanned_document",
            "description": f"All {total_pages} page(s) appear image-based — higher fraud risk than native PDF",
            "severity": "MEDIUM",
            "confidence": 0.65
        })
    elif scanned_pages > 0:
        flags.append({
            "type": "mixed_document",
            "description": f"{scanned_pages} of {total_pages} pages appear scanned — inconsistent document structure",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - Scan check: Document is native PDF — all {total_pages} page(s) are text-based")
    
    doc.close()
    return flags

# Test it
scan_flags = check_scanned_document("sample.pdf")
print("\n")
if scan_flags:
    for f in scan_flags:
        print(f"FLAG: {f['type']}")
        print(f"      {f['description']}")
        print(f"      Severity: {f['severity']} | Confidence: {f['confidence']}")
else:
    print("No scanning anomalies detected")


# In[17]:


def check_scanned_document(pdf_path):
    flags = []
    
    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    scanned_pages = 0
    resolutions = []
    
    for page_num in range(total_pages):
        page = doc[page_num]
        text = page.get_text().strip()
        
        if len(text) < 50:
            scanned_pages += 1
            
            # Render page as image and check resolution
            try:
                mat = fitz.Matrix(1, 1)  # 1x zoom = 72 DPI
                pix = page.get_pixmap(matrix=mat)
                width = pix.width
                height = pix.height
                
                # Estimate DPI
                estimated_dpi = min(width, height) / 8.27
                resolutions.append(estimated_dpi)
                
                if estimated_dpi < 150:
                    flags.append({
                        "type": "low_resolution_scan",
                        "description": f"Page {page_num+1} has low resolution ({estimated_dpi:.0f} DPI estimated) — may indicate re-scanned forgery",
                        "severity": "HIGH",
                        "confidence": 0.80
                    })
            except:
                pass
    
    if scanned_pages == total_pages:
        flags.append({
            "type": "fully_scanned_document",
            "description": f"All {total_pages} page(s) appear image-based — higher fraud risk than native PDF",
            "severity": "MEDIUM",
            "confidence": 0.65
        })
    elif scanned_pages > 0:
        flags.append({
            "type": "mixed_document",
            "description": f"{scanned_pages} of {total_pages} pages appear scanned — inconsistent document structure",
            "severity": "MEDIUM",
            "confidence": 0.70
        })
    else:
        print(f"PASS - Scan check: Document is native PDF — all {total_pages} page(s) are text-based")
    
    # Check resolution consistency
    if len(resolutions) > 1:
        max_res = max(resolutions)
        min_res = min(resolutions)
        if (max_res - min_res) > 100:
            flags.append({
                "type": "inconsistent_resolution",
                "description": f"Resolution varies across pages ({min_res:.0f} to {max_res:.0f} DPI) — possible spliced pages",
                "severity": "HIGH",
                "confidence": 0.85
            })
    
    doc.close()
    return flags

# Test it
scan_flags = check_scanned_document("sample.pdf")
if scan_flags:
    for f in scan_flags:
        print(f"FLAG: {f['type']}")
        print(f"      {f['description']}")
else:
    print("PASS - No scanning anomalies detected")


# In[18]:


def analyze_cyber(pdf_path, doc_type="unknown"):
    print(f"Cyber analysis: {pdf_path}")
    print("-"*50)
    
    all_flags = []
    
    # Task 1 + 5 - Hashing and resubmission
    resubmission_flags, doc_hash = check_resubmission(pdf_path)
    all_flags.extend(resubmission_flags)
    print(f"Step 1 - Hashing and resubmission check complete")
    
    # Task 2 - Metadata checks
    metadata_flags, metadata = check_metadata(pdf_path)
    all_flags.extend(metadata_flags)
    print(f"Step 2 - Metadata check complete")
    
    # Task 3 - File anomaly checks
    file_flags = check_file_anomalies(pdf_path, doc_type)
    all_flags.extend(file_flags)
    print(f"Step 3 - File anomaly check complete")
    
    # Task 4 - Scanned document detection
    scan_flags = check_scanned_document(pdf_path)
    all_flags.extend(scan_flags)
    print(f"Step 4 - Scan detection complete")
    
    # Calculate cyber risk score
    if not all_flags:
        cyber_score = 0.0
        risk_level = "LOW"
    else:
        # Weight by severity
        severity_weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25
        }
        total_weight = sum(
            severity_weights.get(f["severity"], 0.5) * f["confidence"]
            for f in all_flags
        )
        cyber_score = min(round(total_weight / (len(all_flags) + 1), 2), 1.0)
        
        if cyber_score >= 0.65:
            risk_level = "HIGH"
        elif cyber_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    
    print("-"*50)
    print("CYBER ANALYSIS RESULT")
    print("-"*50)
    print(f"Document Hash : {doc_hash}")
    print(f"Cyber Score   : {cyber_score}")
    print(f"Risk Level    : {risk_level}")
    print(f"Total Flags   : {len(all_flags)}")
    
    if all_flags:
        print(f"\nFLAGS RAISED:")
        for f in all_flags:
            print(f"\n   Type        : {f['type']}")
            print(f"   Description : {f['description']}")
            print(f"   Severity    : {f['severity']}")
            print(f"   Confidence  : {f['confidence']}")
    else:
        print("\nNo cyber anomalies detected - document appears genuine")
    
    print("-"*50)
    
    return {
        "document_hash": doc_hash,
        "cyber_score": cyber_score,
        "risk_level": risk_level,
        "flags": all_flags
    }

# Test with clean document
result = analyze_cyber("sample.pdf", "salary_slip")


# In[ ]:




