#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Enhanced Document Fraud Detection System
Detects potential forged financial documents with credibility scoring and annotated PDF output
"""

import fitz  # PyMuPDF
import spacy
import re
import json
import os
from datetime import datetime
import dateutil.parser
from collections import defaultdict


# ============================================================================
# 1. TEXT EXTRACTION
# ============================================================================

def extract_text(pdf_path):
    """Extract text from PDF file"""
    try:
        doc = fitz.open(pdf_path)
        full_text = ""
        for page in doc:
            full_text += page.get_text()
        doc.close()
        return full_text
    except Exception as e:
        raise Exception(f"Error extracting text from PDF: {e}")


def get_pdf_metadata(pdf_path):
    """Extract PDF metadata for forensics"""
    try:
        doc = fitz.open(pdf_path)
        metadata = doc.metadata
        info = {
            "title": metadata.get("title", "Not found"),
            "author": metadata.get("author", "Not found"),
            "subject": metadata.get("subject", "Not found"),
            "creator": metadata.get("creator", "Not found"),
            "producer": metadata.get("producer", "Not found"),
            "creation_date": metadata.get("creationDate", "Not found"),
            "modification_date": metadata.get("modDate", "Not found"),
            "pages": len(doc),
            "encrypted": doc.is_encrypted
        }
        doc.close()
        return info
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 2. NLP AND ENTITY EXTRACTION
# ============================================================================

def load_nlp_model():
    """Load spaCy NER model"""
    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        print("Downloading spaCy model...")
        os.system("python -m spacy download en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")
    return nlp


def extract_entities(text, nlp):
    """Extract named entities from text"""
    doc = nlp(text)
    entities = []
    for ent in doc.ents:
        entities.append({
            "text": ent.text,
            "label": ent.label_,
            "start": ent.start_char,
            "end": ent.end_char
        })
    return entities


def extract_financial_entities(text, nlp):
    """Extract financial entities (money, dates, organizations)"""
    doc = nlp(text)
    
    financial = {
        "money": [],
        "dates": [],
        "organisations": [],
        "numbers": [],
        "persons": []
    }
    
    for ent in doc.ents:
        if ent.label_ == "MONEY":
            financial["money"].append({"text": ent.text, "pos": (ent.start_char, ent.end_char)})
        elif ent.label_ == "DATE":
            financial["dates"].append({"text": ent.text, "pos": (ent.start_char, ent.end_char)})
        elif ent.label_ == "ORG":
            financial["organisations"].append({"text": ent.text, "pos": (ent.start_char, ent.end_char)})
        elif ent.label_ == "CARDINAL":
            financial["numbers"].append({"text": ent.text, "pos": (ent.start_char, ent.end_char)})
        elif ent.label_ == "PERSON":
            financial["persons"].append({"text": ent.text, "pos": (ent.start_char, ent.end_char)})
    
    return financial


# ============================================================================
# 3. SPECIFIC VALUE EXTRACTION WITH POSITIONS
# ============================================================================

def extract_specific_values(text):
    """Extract specific financial values with their positions"""
    values = {}
    positions = {}
    
    patterns = {
        "gross_salary": r"(?:Gross\s+Salary|Gross\s+Pay)[:\s₹,]*([0-9,]+)",
        "net_salary": r"(?:Net\s+Salary|Net\s+Pay)[:\s₹,]*([0-9,]+)",
        "tds": r"TDS[^0-9₹]*[₹\s]*([0-9,]+)",
        "annual_ctc": r"(?:Annual\s+CTC|Total\s+CTC)[:\s₹,]*([0-9,]+)",
        "annual_tds": r"Annual\s+TDS[:\s₹,]*([0-9,]+)",
        "pan": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",
        "ifsc": r"[A-Z]{4}0[A-Z0-9]{6}"
    }
    
    for key, pattern in patterns.items():
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            match = matches[0]
            if key in ["pan", "ifsc"]:
                values[key] = match.group(0)
            else:
                cleaned = match.group(1).replace(",", "")
                values[key] = float(cleaned)
            positions[key] = (match.start(), match.end())
        else:
            values[key] = None
            positions[key] = None
    
    return values, positions


# ============================================================================
# 4. DOCUMENT TYPE DETECTION
# ============================================================================

def detect_document_type(text):
    """Detect the type of financial document"""
    text_lower = text.lower()
    
    document_keywords = {
        "salary_slip": [
            "gross salary", "net salary", "basic salary",
            "hra", "provident fund", "salary slip", "payslip", "employee"
        ],
        "form_16": [
            "form 16", "tds certificate", "assessment year",
            "total income", "deductions under chapter", "part a", "part b"
        ],
        "bank_statement": [
            "account statement", "opening balance", "closing balance",
            "transaction date", "debit", "credit", "balance brought forward"
        ],
        "itr": [
            "income tax return", "assessment year", "gross total income",
            "tax payable", "schedule", "itr-1", "itr-2", "verification"
        ],
        "property_valuation": [
            "property valuation", "market value", "plot area",
            "built up area", "circle rate", "valuation report"
        ]
    }
    
    scores = {}
    for doc_type, keywords in document_keywords.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        scores[doc_type] = score
    
    detected_type = max(scores, key=scores.get) if max(scores.values()) > 0 else "unknown"
    max_score = max(scores.values())
    confidence = max_score / len(document_keywords[detected_type]) if detected_type != "unknown" else 0
    
    return {
        "document_type": detected_type,
        "confidence": round(confidence, 2),
        "all_scores": scores
    }


# ============================================================================
# 5. CONSISTENCY CHECKS
# ============================================================================

def check_inconsistencies(values):
    """Check for financial inconsistencies"""
    flags = []
    
    # Check 1: TDS vs Annual CTC
    if values.get("annual_tds") and values.get("annual_ctc"):
        tds_percentage = (values["annual_tds"] / values["annual_ctc"]) * 100
        if tds_percentage < 5 or tds_percentage > 30:
            flags.append({
    "type":"annual_tds_mismatch",
    "severity":"HIGH",
    "confidence":0.95,
    "highlight_text":annual.group(1),
    "description":f"Expected {expected}, found {a}"
})
    
    # Check 2: Net Salary vs Gross Salary
    if values.get("gross_salary") and values.get("net_salary"):
        if values["gross_salary"] < values["net_salary"]:
            flags.append({
                "type": "salary_logic_error",
                "description": f"Net salary (₹{values['net_salary']:,.0f}) exceeds gross salary (₹{values['gross_salary']:,.0f})",
                "severity": "CRITICAL",
                "confidence": 0.95
            })
        else:
            difference = values["gross_salary"] - values["net_salary"]
            deduction_percentage = (difference / values["gross_salary"]) * 100
            if deduction_percentage < 5 or deduction_percentage > 50:
                flags.append({
                    "type": "salary_deduction_mismatch",
                    "description": f"Deductions are {deduction_percentage:.1f}% of gross — outside normal range (5-50%)",
                    "severity": "MEDIUM",
                    "confidence": 0.80
                })
    
    # Check 3: Annual CTC vs Monthly Gross
    if values.get("annual_ctc") and values.get("gross_salary"):
        expected_annual = values["gross_salary"] * 12
        if expected_annual > 0:
            difference_percentage = abs(expected_annual - values["annual_ctc"]) / values["annual_ctc"] * 100
            if difference_percentage > 20:
                flags.append({
                    "type": "ctc_mismatch",
                    "description": f"Annual CTC differs from Gross×12 by {difference_percentage:.1f}%",
                    "severity": "HIGH",
                    "confidence": 0.90
                })
    
    return flags


def validate_pan(text):

    flags = []

    pan_pattern = r'[A-Z]{5}[0-9]{4}[A-Z]'
    pan_matches = re.findall(pan_pattern, text.upper())

    valid_entities = ['P','C','H','F','A','T','B','L','J','G']

    if not pan_matches:

        flags.append({
            "type": "pan_missing",
            "description": "No PAN found",
            "severity": "MEDIUM",
            "confidence": 0.80
        })

        return flags

    for pan in pan_matches:

        entity_type = pan[3]

        if entity_type not in valid_entities:

            flags.append({
                "type": "pan_invalid_entity",
                "description": f"PAN {pan} has invalid entity type '{entity_type}'",
                "severity": "HIGH",
                "confidence": 0.90,
                "highlight_text": pan
            })

    return flags

def validate_gross_salary(text):

    flags = []

    pattern = r'₹?([0-9,]+)'

    basic = re.search(r'Basic Salary.*?([0-9,]+)', text)
    hra = re.search(r'House Rent Allowance.*?([0-9,]+)', text)
    conv = re.search(r'Conveyance Allowance.*?([0-9,]+)', text)
    med = re.search(r'Medical Allowance.*?([0-9,]+)', text)
    spl = re.search(r'Special Allowance.*?([0-9,]+)', text)
    gross = re.search(r'Gross Salary.*?([0-9,]+)', text)

    if all([basic,hra,conv,med,spl,gross]):

        calculated = (
            int(basic.group(1).replace(",",""))
            + int(hra.group(1).replace(",",""))
            + int(conv.group(1).replace(",",""))
            + int(med.group(1).replace(",",""))
            + int(spl.group(1).replace(",",""))
        )

        document_gross = int(
            gross.group(1).replace(",","")
        )

        if calculated != document_gross:

            flags.append({
    "type":"gross_salary_mismatch",
    "severity":"CRITICAL",
    "confidence":0.99,
    "highlight_text":gross.group(1),
    "description":f"Expected {calculated}, found {document_gross}"
})

    return flags

def check_date_consistency(text, nlp):
    """Check for date inconsistencies"""
    flags = []
    doc = nlp(text)
    
    dates_found = [ent.text for ent in doc.ents if ent.label_ == "DATE"]
    parsed_dates = []
    
    for date_str in dates_found:
        try:
            parsed = dateutil.parser.parse(date_str, fuzzy=True)
            parsed_dates.append({"original": date_str, "parsed": parsed})
        except:
            pass
    
    # Check for future dates
    today = datetime.now()
    for d in parsed_dates:
        if d["parsed"] > today:
            flags.append({
                "type": "future_date",
                "description": f"Document contains a future date: {d['original']}",
                "severity": "HIGH",
                "confidence": 0.85
            })
    
    # Check for suspicious date range
    if len(parsed_dates) >= 2:
        all_dates = [d["parsed"] for d in parsed_dates]
        date_range = (max(all_dates) - min(all_dates)).days
        if date_range > 365:
            flags.append({
                "type": "date_range_suspicious",
                "description": f"Document dates span {date_range} days — suspicious for a single document",
                "severity": "MEDIUM",
                "confidence": 0.75
            })
    
    return flags, parsed_dates

def validate_annual_tds(text):

    flags = []

    monthly = re.search(
        r'TDS.*?([0-9,]+)',
        text
    )

    annual = re.search(
        r'Annual TDS.*?([0-9,]+)',
        text
    )

    if monthly and annual:

        m = int(monthly.group(1).replace(",",""))
        a = int(annual.group(1).replace(",",""))

        expected = m * 12

        if expected != a:

            flags.append({
                "type":"annual_tds_mismatch",
                "severity":"HIGH",
                "confidence": 0.95,
                "highlight_text":annual.group(1),
                "description":
                f"Expected {expected}, found {a}"
            })

    return flags

def validate_cin(text):

    flags = []

    cin_match = re.search(
        r'CIN[: ]*([A-Z0-9]+)',
        text
    )

    if not cin_match:
        return flags

    cin = cin_match.group(1)

    pattern = r'^[LU][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$'

    if not re.match(pattern, cin):

        flags.append({
    "type":"invalid_cin",
    "severity":"HIGH",
    "confidence":0.95,
    "highlight_text":cin,
    "description":"Invalid CIN format"
})

    return flags

def detect_multiple_pans(text):

    pans = re.findall(
        r'[A-Z]{5}[0-9]{4}[A-Z]',
        text
    )

    unique = list(set(pans))

    if len(unique) > 1:

        return [{
            "type":"multiple_pan_numbers",
            "severity":"HIGH",
            "confidence":0.95,
            "highlight_text":unique[1],
            "description":
            f"{len(unique)} PAN numbers detected"
        }]

    return []


def detect_ocr_errors(text):

    flags = []

    suspicious = re.findall(
        r'[0-9]+[A-Za-z]+[0-9,]*',
        text
    )

    for item in suspicious:

        flags.append({
    "type":"ocr_corruption",
    "severity":"MEDIUM",
    "confidence":0.75,
    "highlight_text":item,
    "description":"Possible OCR corruption"
})

    return flags


def detect_negative_amounts(text):

    flags = []

    negatives = re.findall(
        r'-₹?\s*[0-9,]+',
        text
    )

    for value in negatives:

        flags.append({
    "type":"negative_amount",
    "severity":"MEDIUM",
    "confidence":0.90,
    "highlight_text":value,
    "description":"Negative monetary value"
})

    return flags

def detect_multiple_ifsc(text):

    ifscs = re.findall(
        r'[A-Z]{4}0[A-Z0-9]{6}',
        text
    )

    unique = set(ifscs)

    if len(unique) > 1:

        return [{
        "type":"multiple_pan_numbers",
        "severity":"HIGH",
        "confidence":0.95,
            "highlight_text":list(unique)[0],
            "description":
            f"{len(unique)} IFSC codes found"
        }]

    return []

def check_income_vs_profession(text, specific_values):
    """Check if income matches declared profession"""
    flags = []
    
    profession_salary_ranges = {
        "peon": (5000, 20000),
        "clerk": (15000, 40000),
        "assistant": (20000, 60000),
        "officer": (40000, 120000),
        "manager": (60000, 250000),
        "branch manager": (80000, 300000),
        "senior manager": (100000, 400000),
        "deputy manager": (80000, 250000),
        "director": (200000, 1000000),
        "engineer": (30000, 200000),
        "software engineer": (50000, 300000),
        "analyst": (40000, 200000),
        "consultant": (60000, 400000),
        "developer": (40000, 250000),
        "accountant": (20000, 80000),
        "teacher": (20000, 80000),
        "professor": (50000, 150000),
        "doctor": (50000, 300000),
        "nurse": (20000, 60000)
    }
    
    text_lower = text.lower()
    gross_salary = specific_values.get("gross_salary")
    
    if not gross_salary:
        return flags
    
    matched_profession = None
    salary_range = None
    
    for profession, range_ in profession_salary_ranges.items():
        if profession in text_lower:
            matched_profession = profession
            salary_range = range_
            break
    
    if matched_profession and salary_range:
        min_sal, max_sal = salary_range
        if gross_salary < min_sal:
            flags.append({
                "type": "income_too_low",
                "description": f"Salary ₹{gross_salary:,.0f} is below minimum for {matched_profession} (min: ₹{min_sal:,})",
                "severity": "MEDIUM",
                "confidence": 0.80
            })
        elif gross_salary > max_sal:
            flags.append({
                "type": "income_too_high",
                "description": f"Salary ₹{gross_salary:,.0f} exceeds maximum for {matched_profession} (max: ₹{max_sal:,})",
                "severity": "MEDIUM",
                "confidence": 0.80
            })
    
    return flags


def check_ifsc_consistency(text):
    """Check IFSC code consistency with bank name"""
    flags = []
    
    bank_ifsc_map = {
        "canara bank": "CNRB",
        "state bank of india": "SBIN",
        "hdfc bank": "HDFC",
        "icici bank": "ICIC",
        "axis bank": "UTIB",
        "punjab national bank": "PUNB",
        "bank of baroda": "BARB",
        "union bank": "UBIN",
        "kotak mahindra bank": "KKBK",
        "yes bank": "YESB",
        "idbi bank": "IBKL",
        "indian bank": "IDIB",
        "central bank": "CBIN",
        "bank of india": "BKID"
    }
    
    ifsc_pattern = r'[A-Z]{4}0[A-Z0-9]{6}'
    ifsc_matches = re.findall(ifsc_pattern, text.upper())
    text_lower = text.lower()
    
    if not ifsc_matches:
        flags.append({
            "type": "ifsc_missing",
            "description": "No IFSC code found in document",
            "severity": "LOW",
            "confidence": 0.70
        })
        return flags
    
    for ifsc in ifsc_matches:
        ifsc_prefix = ifsc[:4]
        matched_bank = None
        expected_prefix = None
        
        for bank, prefix in bank_ifsc_map.items():
            if bank in text_lower:
                matched_bank = bank
                expected_prefix = prefix
                break
        
        if matched_bank and expected_prefix:
            if ifsc_prefix != expected_prefix:
                flags.append({
                    "type": "ifsc_bank_mismatch",
                    "description": f"IFSC {ifsc} prefix '{ifsc_prefix}' doesn't match {matched_bank} (expected '{expected_prefix}')",
                    "severity": "HIGH",
                    "confidence": 0.90
                })
    
    return flags


def verify_company(text, nlp):
    """Verify company against whitelist"""
    company_whitelist = {
        "Canara Bank Ltd": "L85110KA1969GOI001856",
        "State Bank of India": "L64190MH1955GOI008712",
        "Infosys Ltd": "L85110KA1981PLC013115",
        "Tata Consultancy Services": "L22210MH1995PLC084781",
        "Wipro Ltd": "L32102KA1945PLC020800",
        "HDFC Bank Ltd": "L65920MH1994PLC080618",
        "ICICI Bank Ltd": "L65190GJ1994PLC021012",
        "Reliance Industries Ltd": "L17110MH1973PLC019786"
    }
    
    IGNORE_ORGS = [
        "cin", "pan", "tds", "income tax", "professional tax",
        "ifsc", "hra", "ctc", "epf", "pf", "provident fund",
        "basic salary", "net salary", "gross salary"
    ]
    
    doc = nlp(text)
    found_orgs = [
        ent.text for ent in doc.ents 
        if ent.label_ == "ORG" 
        and ent.text.lower() not in IGNORE_ORGS
        and len(ent.text) > 4
    ]
    
    flags = []
    verified = []
    
    for org in found_orgs:
        matched = False
        for company in company_whitelist.keys():
            if org.lower() in company.lower() or company.lower() in org.lower():
                matched = True
                verified.append({
                    "found": org,
                    "matched_to": company,
                    "cin": company_whitelist[company]
                })
                break
        
        if not matched:
            flags.append({
                "type": "unverified_company",
                "description": f"Company '{org}' not found in verified whitelist",
                "severity": "MEDIUM",
                "confidence": 0.75
            })
    
    return verified, flags


# ============================================================================
# 6. RISK SCORING AND CREDIBILITY
# ============================================================================

def calculate_risk_score(flags):
    """Calculate overall risk score"""
    if not flags:
        return {
            "score": 0.0,
            "risk_level": "LOW",
            "summary": "No inconsistencies detected. Document appears genuine.",
            "flags": [],
            "flag_count": 0,
            "critical_count": 0,
            "high_count": 0
        }
    
    critical_flags = [f for f in flags if f.get("severity") == "CRITICAL"]
    high_flags = [f for f in flags if f.get("severity") == "HIGH"]
    
    critical_weight = len(critical_flags) * 0.5
    high_weight = len(high_flags) * 0.25
    medium_weight = (len(flags) - len(critical_flags) - len(high_flags)) * 0.1
    
    total_score = min(critical_weight + high_weight + medium_weight, 1.0)
    
    if total_score >= 0.70:
        risk_level = "CRITICAL"
    elif total_score >= 0.50:
        risk_level = "HIGH"
    elif total_score >= 0.25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "score": round(total_score, 2),
        "risk_level": risk_level,
        "summary": f"{len(flags)} inconsistencies detected in document.",
        "flags": flags,
        "flag_count": len(flags),
        "critical_count": len(critical_flags),
        "high_count": len(high_flags)
    }

from datetime import datetime
import re

def detect_future_dates(text):

    flags = []

    current_year = datetime.now().year

    # Month name + year
    month_pattern = r'(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}'

    month_dates = re.findall(
        month_pattern,
        text,
        re.IGNORECASE
    )

    full_matches = re.finditer(
        month_pattern,
        text,
        re.IGNORECASE
    )

    for match in full_matches:

        date_text = match.group(0)

        try:

            dt = datetime.strptime(
                date_text,
                "%B %Y"
            )

            if dt.year > current_year:

                flags.append({
                    "type": "FUTURE_DATE",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "highlight_text": date_text,
                    "description":
                        f"Document contains a future date: {date_text}"
                })

        except:
            pass

    # Standalone years
    years = re.findall(r'\b(20\d{2})\b', text)

    for y in years:

        if int(y) > current_year:

            flags.append({
                "type": "FUTURE_DATE",
                "severity": "HIGH",
                "confidence": 0.85,
                "highlight_text": y,
                "description":
                    f"Document contains a future year: {y}"
            })

    return flags

def calculate_credibility_score(values, verified_companies, pdf_metadata, doc_type):
    """Calculate credibility score based on multiple factors"""
    credibility_factors = {}
    
    # Factor 1: Financial data completeness (0-25 points)
    required_fields = ["gross_salary", "net_salary", "annual_ctc", "tds"]
    present_fields = sum(1 for field in required_fields if values.get(field) is not None)
    completeness_score = (present_fields / len(required_fields)) * 25
    credibility_factors["financial_completeness"] = round(completeness_score, 1)
    
    # Factor 2: Document metadata (0-15 points)
    metadata_score = 0
    if pdf_metadata.get("creator") and pdf_metadata.get("creator") != "Not found":
        metadata_score += 5
    if pdf_metadata.get("creation_date") and pdf_metadata.get("creation_date") != "Not found":
        metadata_score += 5
    if not pdf_metadata.get("encrypted", False):
        metadata_score += 5
    credibility_factors["metadata_quality"] = metadata_score
    
    # Factor 3: Company verification (0-20 points)
    company_score = 0
    if verified_companies:
        company_score = 20
    credibility_factors["company_verification"] = company_score
    
    # Factor 4: PAN validation (0-15 points)
    if values.get("pan"):
        credibility_factors["pan_present"] = 15
    else:
        credibility_factors["pan_present"] = 0
    
    # Factor 5: Document type confidence (0-10 points)
    doc_confidence = min(doc_type.get("confidence", 0) * 10, 10)
    credibility_factors["document_type_confidence"] = round(doc_confidence, 1)
    
    # Factor 6: IFSC code validation (0-15 points)
    if values.get("ifsc"):
        credibility_factors["ifsc_present"] = 15
    else:
        credibility_factors["ifsc_present"] = 0
    
    total_credibility = sum(credibility_factors.values())
    credibility_percentage = round((total_credibility / 100) * 100, 1)
    
    return {
        "score": credibility_percentage,
        "factors": credibility_factors,
        "total_points": round(total_credibility, 1),
        "max_points": 100
    }


# ============================================================================
# 7. PDF ANNOTATION
# ============================================================================


def annotate_pdf_with_flags(pdf_path, output_path, flags):
    """
    Highlight suspicious text directly inside the PDF.
    """

    color_map = {
        "CRITICAL": (1, 0, 0),      # Red
        "HIGH": (1, 0.5, 0),        # Orange
        "MEDIUM": (1, 1, 0),        # Yellow
        "LOW": (0, 0, 1)            # Blue
    }

    doc = fitz.open(pdf_path)
    total_annotations = 0

    for flag in flags:

        text_to_find = flag.get("highlight_text")

        if not text_to_find:
            continue

        for page in doc:

            matches = page.search_for(str(text_to_find))

            for rect in matches:

                annot = page.add_highlight_annot(rect)

                annot.set_colors(
                    stroke=color_map.get(
                        flag.get("severity", "LOW"),
                        (1, 0, 0)
                    )
                )

                annot.set_info(
                    title="Fraud Detector",
                    content=flag.get("description", "")
                )

                annot.update()
                total_annotations += 1

    doc.save(
        output_path,
        garbage=4,
        deflate=True
    )

    doc.close()

    print("\n===================================")
    print("ANNOTATED PDF CREATED")
    print("===================================")
    print("File:", os.path.abspath(output_path))
    print("Highlights Added:", total_annotations)
    print("===================================\n")

    return output_path

# ============================================================================
# 8. COMPREHENSIVE ANALYSIS
# ============================================================================

def analyze_document(pdf_path):
    """Complete document analysis pipeline"""
    print(f"\n{'='*70}")
    print(f"DOCUMENT FRAUD DETECTION ANALYSIS")
    print(f"{'='*70}")
    print(f"File: {pdf_path}")
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    # Load NLP model
    nlp = load_nlp_model()
    
    # Step 1: Extract text and metadata
    print("[1/8] Extracting text and metadata...")
    text = extract_text(pdf_path)
    pdf_metadata = get_pdf_metadata(pdf_path)
    
    # Step 2: Detect document type
    print("[2/8] Detecting document type...")
    doc_type = detect_document_type(text)
    
    # Step 3: Extract entities
    print("[3/8] Extracting financial entities...")
    financial_entities = extract_financial_entities(text, nlp)
    specific_values, positions = extract_specific_values(text)
    
    # Step 4: Run consistency checks
    print("[4/8] Running financial consistency checks...")
    financial_flags = check_inconsistencies(specific_values)
    pan_flags = validate_pan(text)
    date_flags, parsed_dates = check_date_consistency(text, nlp)
    profession_flags = check_income_vs_profession(text, specific_values)
    ifsc_flags = check_ifsc_consistency(text)
    
    # Step 5: Verify company
    print("[5/8] Verifying company information...")
    verified, company_flags = verify_company(text, nlp)
    
    # Step 6: Combine all flags
    print("[6/8] Calculating risk scores...")
    all_flags = (financial_flags +
    pan_flags +
    date_flags +
    profession_flags +
    ifsc_flags +
    company_flags +

    validate_gross_salary(text) +
    validate_annual_tds(text) +
    validate_cin(text) +
    detect_multiple_pans(text) +
    detect_ocr_errors(text) +
    detect_negative_amounts(text) +
    detect_multiple_ifsc(text)+detect_future_dates(text)     
)
    risk_result = calculate_risk_score(all_flags)
    
    # Step 7: Calculate credibility
    print("[7/8] Calculating credibility score...")
    credibility = calculate_credibility_score(specific_values, verified, pdf_metadata, doc_type)
    
    # Step 8: Create annotated PDF
    print("[8/8] Creating annotated PDF...")
    output_pdf = pdf_path.replace(".pdf", "_flagged.pdf")
    annotate_pdf_with_flags(pdf_path, output_pdf, all_flags)
    
    # ========================================================================
    # RESULTS DISPLAY
    # ========================================================================
    
    print(f"\n{'='*70}")
    print("ANALYSIS RESULTS")
    print(f"{'='*70}\n")
    
    # Document Information
    print("📄 DOCUMENT INFORMATION")
    print(f"  Type: {doc_type['document_type'].upper()} (confidence: {doc_type['confidence']})")
    print(f"  Pages: {pdf_metadata.get('pages', 'Unknown')}")
    print(f"  Encrypted: {'Yes' if pdf_metadata.get('encrypted') else 'No'}")
    print(f"  Creator: {pdf_metadata.get('creator', 'Unknown')}")
    
    # Financial Data
    print(f"\n💰 EXTRACTED FINANCIAL DATA")
    if specific_values.get("gross_salary"):
        print(f"  Gross Salary: ₹{specific_values['gross_salary']:,.0f}")
    if specific_values.get("net_salary"):
        print(f"  Net Salary: ₹{specific_values['net_salary']:,.0f}")
    if specific_values.get("annual_ctc"):
        print(f"  Annual CTC: ₹{specific_values['annual_ctc']:,.0f}")
    if specific_values.get("annual_tds"):
        print(f"  Annual TDS: ₹{specific_values['annual_tds']:,.0f}")
    if specific_values.get("pan"):
        print(f"  PAN: {specific_values['pan']}")
    if specific_values.get("ifsc"):
        print(f"  IFSC: {specific_values['ifsc']}")
    
    # Entities Found
    print(f"\n🏢 ENTITIES FOUND")
    print(f"  Organizations: {len(financial_entities['organisations'])}")
    print(f"  Persons: {len(financial_entities['persons'])}")
    print(f"  Dates: {len(financial_entities['dates'])}")
    print(f"  Money Values: {len(financial_entities['money'])}")
    print(f"  Numbers: {len(financial_entities['numbers'])}")
    
    # Verified Companies
    if verified:
        print(f"\n✅ VERIFIED COMPANIES")
        for v in verified:
            print(f"  {v['found']} → {v['matched_to']}")
            print(f"    CIN: {v['cin']}")
    
    # Risk Assessment
    print(f"\n⚠️  RISK ASSESSMENT")
    print(f"  Risk Level: {risk_result['risk_level']}")
    print(f"  Risk Score: {risk_result['score']:.2f} / 1.00")
    print(f"  Total Flags: {risk_result['flag_count']}")
    print(f"  Critical Flags: {risk_result['critical_count']}")
    print(f"  High Severity Flags: {risk_result['high_count']}")
    
    # Credibility Score
    print(f"\n🔐 CREDIBILITY ASSESSMENT")
    print(f"  Credibility Score: {credibility['score']:.1f}%")
    print(f"  Total Points: {credibility['total_points']} / {credibility['max_points']}")
    print(f"\n  Credibility Breakdown:")
    for factor, score in credibility['factors'].items():
        factor_name = factor.replace("_", " ").title()
        print(f"    • {factor_name}: {score} points")
    
    # Detailed Flags
    if risk_result['flags']:
        print(f"\n🚨 DETAILED FLAGS ({len(risk_result['flags'])} issues)")
        
        # Group by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for severity in severity_order:
            severity_flags = [f for f in risk_result['flags'] if f.get('severity') == severity]
            if severity_flags:
                print(f"\n  {severity} SEVERITY ({len(severity_flags)}):")
                for f in severity_flags:
                    print(f"    • {f['type'].upper()}")
                    print(f"      {f['description']}")
                    print(f"      Confidence: {f['confidence']}")
    else:
        print(f"\n✅ NO ISSUES DETECTED")
        print(f"  Document appears to be genuine")
    
    # Summary
    print(f"\n{'='*70}")
    print("RECOMMENDATION")
    print(f"{'='*70}")
    
    if risk_result['risk_level'] == "CRITICAL":
        print("🛑 REJECT: Document shows critical signs of forgery.")
        print("   Manual verification with issuing authority is MANDATORY.")
    elif risk_result['risk_level'] == "HIGH":
        print("⚠️  REVIEW: Document has multiple issues. Recommend further investigation.")
        print("   Contact issuing authority for verification.")
    elif risk_result['risk_level'] == "MEDIUM":
        print("⚠️  CAUTION: Some inconsistencies found. Verify critical details.")
        print("   Additional documentation may be required.")
    else:
        print("✅ ACCEPT: Document appears to be genuine.")
        print("   No major inconsistencies detected.")
    
    print(f"\n{'='*70}")
    print(f"Annotated PDF: {output_pdf}")
    print(f"{'='*70}\n")
    
    # Return structured result
    return {
        "file": pdf_path,
        "timestamp": datetime.now().isoformat(),
        "document_type": doc_type['document_type'],
        "risk_level": risk_result['risk_level'],
        "risk_score": risk_result['score'],
        "credibility_score": credibility['score'],
        "flags": risk_result['flags'],
        "verified_companies": verified,
        "financial_data": specific_values,
        "metadata": pdf_metadata,
        "annotated_pdf": output_pdf
    }


# ============================================================================
# 9. MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Example usage
    pdf_file = "sample.pdf"  # Change this to your PDF path
    
    if not os.path.exists(pdf_file):
        print(f"Error: File '{pdf_file}' not found.")
        print("Please provide a valid PDF file path.")
    else:
        result = analyze_document(pdf_file)
        
        # Save result as JSON
        json_output = pdf_file.replace(".pdf", "_analysis.json")
        with open(json_output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n✅ Analysis saved to: {json_output}")