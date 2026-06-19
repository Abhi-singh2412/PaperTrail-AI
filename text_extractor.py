#!/usr/bin/env python
# coding: utf-8

# In[1]:


pip install pymupdf


# In[1]:


import fitz  # this is PyMuPDF

def extract_text(pdf_path):
    doc = fitz.open(pdf_path)
    full_text = ""
    for page in doc:
        full_text += page.get_text()
    return full_text

# Test it
text = extract_text("sample.pdf")
print(text)


# In[3]:


pip install spacy


# In[10]:


get_ipython().system('python -m spacy download en_core_web_sm')


# In[2]:


import spacy

nlp = spacy.load("en_core_web_sm")

def extract_entities(text):
    doc = nlp(text)
    entities = []
    for ent in doc.ents:
        entities.append({
            "text": ent.text,
            "label": ent.label_
        })
    return entities


entities = extract_entities(text)
for e in entities:
    print(e)


# In[3]:


def extract_financial_entities(text):
    doc = nlp(text)
    
    financial = {
        "money": [],
        "dates": [],
        "organisations": [],
        "numbers": []
    }
    
    for ent in doc.ents:
        if ent.label_ == "MONEY":
            financial["money"].append(ent.text)
        elif ent.label_ == "DATE":
            financial["dates"].append(ent.text)
        elif ent.label_ == "ORG":
            financial["organisations"].append(ent.text)
        elif ent.label_ == "CARDINAL":
            financial["numbers"].append(ent.text)
    
    return financial


financial_data = extract_financial_entities(text)
for key, values in financial_data.items():
    print(f"\n{key.upper()}:")
    for v in values:
        print(f"  - {v}")


# In[30]:


import re

def extract_specific_values(text):
    values = {}
    
    # Patterns to search for specific financial fields
    patterns = {
        "gross_salary": r"Gross Salary[:\s₹,]*([0-9,]+)",
        "net_salary": r"Net Salary[:\s₹,]*([0-9,]+)",
        "tds": r"TDS[^0-9₹]*[₹\s]*([0-9,]+)",
        "annual_ctc": r"Annual CTC[:\s₹,]*([0-9,]+)",
        "annual_tds": r"Annual TDS[:\s₹,]*([0-9,]+)"
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            cleaned = match.group(1).replace(",", "")
            values[key] = float(cleaned)
        else:
            values[key] = None
    
    return values


specific_values = extract_specific_values(text)
for key, val in specific_values.items():
    print(f"{key}: ₹{val:,.0f}" if val else f"{key}: Not found")


# In[31]:


def check_inconsistencies_v2(values):
    flags = []

    # Check 1 — TDS vs Annual CTC
    if values["annual_tds"] and values["annual_ctc"]:
        tds_percentage = (values["annual_tds"] / values["annual_ctc"]) * 100
        if tds_percentage < 5 or tds_percentage > 30:
            flags.append({
                "type": "tds_mismatch",
                "description": f"Annual TDS is {tds_percentage:.1f}% of Annual CTC — expected 5-30%",
                "confidence": 0.85
            })
        else:
            print(f"TDS check passed — {tds_percentage:.1f}% of Annual CTC")

    # Check 2 — Net Salary vs Gross Salary
    if values["gross_salary"] and values["net_salary"]:
        difference = values["gross_salary"] - values["net_salary"]
        # Difference should be reasonable (deductions usually 10-40% of gross)
        deduction_percentage = (difference / values["gross_salary"]) * 100
        if deduction_percentage < 5 or deduction_percentage > 50:
            flags.append({
                "type": "salary_deduction_mismatch",
                "description": f"Deductions are {deduction_percentage:.1f}% of gross — outside normal range (5-50%)",
                "confidence": 0.80
            })
        else:
            print(f"Salary deduction check passed — {deduction_percentage:.1f}% deducted")

    # Check 3 — Annual CTC vs Monthly Gross
    if values["annual_ctc"] and values["gross_salary"]:
        expected_annual = values["gross_salary"] * 12
        difference_percentage = abs(expected_annual - values["annual_ctc"]) / values["annual_ctc"] * 100
        if difference_percentage > 20:
            flags.append({
                "type": "ctc_mismatch",
                "description": f"Annual CTC differs from Gross×12 by {difference_percentage:.1f}%",
                "confidence": 0.90
            })
        else:
            print(f"CTC check passed — within {difference_percentage:.1f}% of Gross×12")

    return flags

# Test it
flags = check_inconsistencies_v2(specific_values)
print("\n")
if flags:
    for flag in flags:
        print(f"🚨 FLAG: {flag['type']}")
        print(f"   {flag['description']}")
        print(f"   Confidence: {flag['confidence']}")
else:
    print("No inconsistencies found")


# In[32]:


# Simulating a forged document

forged_values = {
    "gross_salary": 250000,   # inflated from 135,950
    "net_salary": 111050,     # forgot to change this
    "tds": 14500,             # forgot to change this
    "annual_ctc": 1631400,    # forgot to change this
    "annual_tds": 174000      # forgot to change this
}

print("Testing with FORGED document values:")
print("="*45)
flags = check_inconsistencies_v2(forged_values)
print("\n")
if flags:
    for flag in flags:
        print(f"FLAG: {flag['type']}")
        print(f"{flag['description']}")
        print(f"Confidence: {flag['confidence']}")
else:
    print("No inconsistencies found")


# In[33]:


def calculate_risk_score(flags):
    if not flags:
        return {
            "score": 0.0,
            "risk_level": "LOW",
            "summary": "No inconsistencies detected. Document appears genuine.",
            "flags": []
        }
    
    # Weight each flag by its confidence
    total_confidence = sum(f["confidence"] for f in flags)
    score = min(total_confidence / (len(flags) + 1), 1.0)
    
    if score >= 0.65:
        risk_level = "HIGH"
    elif score >= 0.35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "score": round(score, 2),
        "risk_level": risk_level,
        "summary": f"{len(flags)} inconsistencies detected in document.",
        "flags": flags
    }

# Test with forged document flags
result = calculate_risk_score(flags)
print(f"Risk Score  : {result['score']}")
print(f"Risk Level  : {result['risk_level']}")
print(f"Summary     : {result['summary']}")
print(f"\nFlags:")
for f in result["flags"]:
    print(f"{f['type']} — {f['description']}")


# In[34]:


def analyze_document(pdf_path):
    print(f"Analyzing: {pdf_path}")
    print("="*45)
    
    # Step 1 - Extract text
    text = extract_text(pdf_path)
    print("Step 1 — Text extracted")
    
    # Step 2 - Extract financial entities
    financial_data = extract_financial_entities(text)
    print("Step 2 — Financial entities extracted")
    
    # Step 3 - Extract specific values
    specific_values = extract_specific_values(text)
    print("Step 3 — Specific values extracted")
    
    # Step 4 - Check inconsistencies
    flags = check_inconsistencies_v2(specific_values)
    print(f"Step 4 — Inconsistency check complete")
    
    # Step 5 - Calculate risk score
    result = calculate_risk_score(flags)
    print("Step 5 — Risk score calculated")
    
    print("="*45)
    print(f"\n FINAL RESULT:")
    print(f"Risk Score  : {result['score']}")
    print(f"Risk Level  : {result['risk_level']}")
    print(f"Summary     : {result['summary']}")
    if result["flags"]:
        print(f"\nFlags raised:")
        for f in result["flags"]:
            print(f"     {f['type']}")
            print(f"     {f['description']}")
            print(f"     Confidence: {f['confidence']}")
    
    return result

# Test it
final_result = analyze_document("sample.pdf")


# In[36]:


import json

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

# Saving it as a local JSON file
with open("company_whitelist.json", "w") as f:
    json.dump(company_whitelist, f, indent=4)

print("Company whitelist created successfully")


# In[37]:


def verify_company(text):
    # Load whitelist
    with open("company_whitelist.json", "r") as f:
        whitelist = json.load(f)
    
    # Extract organisations from text
    doc = nlp(text)
    found_orgs = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
    
    flags = []
    verified = []
    
    for org in found_orgs:
        # Check if org matches any whitelist entry
        matched = False
        for company in whitelist.keys():
            if org.lower() in company.lower() or company.lower() in org.lower():
                matched = True
                verified.append({
                    "found": org,
                    "matched_to": company,
                    "cin": whitelist[company]
                })
                break
        
        if not matched:
            flags.append({
                "type": "unverified_company",
                "description": f"Company '{org}' not found in verified whitelist",
                "confidence": 0.75
            })
    
    return verified, flags


verified, company_flags = verify_company(text)

print("VERIFIED COMPANIES:")
for v in verified:
    print(f"  {v['found']} → {v['matched_to']} (CIN: {v['cin']})")

print(f"\nUNVERIFIED COMPANIES:")
if company_flags:
    for f in company_flags:
        print(f"  {f['description']}")
else:
    print("  None — all companies verified")


# In[38]:


# Keywords that spaCy wrongly tags as organisations
IGNORE_ORGS = [
    "cin", "pan", "tds", "income tax", "professional tax",
    "ifsc", "hra", "ctc", "epf", "pf", "provident fund",
    "basic salary", "net salary", "gross salary"
]

def verify_company_v2(text):
    # Load whitelist
    with open("company_whitelist.json", "r") as f:
        whitelist = json.load(f)
    
    # Extracting organisations from text
    doc = nlp(text)
    found_orgs = [
        ent.text for ent in doc.ents 
        if ent.label_ == "ORG" 
        and ent.text.lower() not in IGNORE_ORGS
        and len(ent.text) > 4  # ignore very short tags
    ]
    
    flags = []
    verified = []
    
    for org in found_orgs:
        matched = False
        for company in whitelist.keys():
            if org.lower() in company.lower() or company.lower() in org.lower():
                matched = True
                verified.append({
                    "found": org,
                    "matched_to": company,
                    "cin": whitelist[company]
                })
                break
        
        if not matched:
            flags.append({
                "type": "unverified_company",
                "description": f"Company '{org}' not found in verified whitelist",
                "confidence": 0.75
            })
    
    return verified, flags


verified, company_flags = verify_company_v2(text)

print("VERIFIED COMPANIES:")
for v in verified:
    print(f"  {v['found']} → {v['matched_to']} (CIN: {v['cin']})")

print(f"\nUNVERIFIED COMPANIES:")
if company_flags:
    for f in company_flags:
        print(f"  {f['description']}")
else:
    print("  None — all companies verified")


# In[40]:


import re

def is_cin_number(text):
    # CIN format: L/U + 5 digits + 2 letters + 4 digits + 3 letters + 6 digits
    cin_pattern = r'^[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}$'
    return bool(re.match(cin_pattern, text.strip()))

def verify_company_v3(text):
    # Load whitelist
    with open("company_whitelist.json", "r") as f:
        whitelist = json.load(f)
    
    # Extract organisations from text
    doc = nlp(text)
    found_orgs = [
        ent.text for ent in doc.ents 
        if ent.label_ == "ORG" 
        and ent.text.lower() not in IGNORE_ORGS
        and len(ent.text) > 4
        and not is_cin_number(ent.text)  # ignore CIN numbers
    ]
    
    flags = []
    verified = []
    
    for org in found_orgs:
        matched = False
        for company in whitelist.keys():
            if org.lower() in company.lower() or company.lower() in org.lower():
                matched = True
                verified.append({
                    "found": org,
                    "matched_to": company,
                    "cin": whitelist[company]
                })
                break
        
        if not matched:
            flags.append({
                "type": "unverified_company",
                "description": f"Company '{org}' not found in verified whitelist",
                "confidence": 0.75
            })
    
    return verified, flags


verified, company_flags = verify_company_v3(text)

print("VERIFIED COMPANIES:")
for v in verified:
    print(f"  {v['found']} → {v['matched_to']} (CIN: {v['cin']})")

print(f"\nUNVERIFIED COMPANIES:")
if company_flags:
    for f in company_flags:
        print(f"  {f['description']}")
else:
    print("  None — all companies verified")


# In[13]:


def analyze_document_v2(pdf_path):
    print(f"Analyzing: {pdf_path}")
    print("="*45)
    
    # Step 1 - Extract text
    text = extract_text(pdf_path)
    print("Step 1 — Text extracted")
    
    # Step 2 - Extract financial entities
    financial_data = extract_financial_entities(text)
    print("Step 2 — Financial entities extracted")
    
    # Step 3 - Extract specific values
    specific_values = extract_specific_values(text)
    print("Step 3 — Specific values extracted")
    
    # Step 4 - Check financial inconsistencies
    financial_flags = check_inconsistencies_v2(specific_values)
    print("Step 4 — Financial inconsistency check complete")
    
    # Step 5 - Verify companies
    verified, company_flags = verify_company_v3(text)
    print("Step 5 — Company verification complete")
    
    # Step 6 - Combine all flags
    all_flags = financial_flags + company_flags
    
    # Step 7 - Calculate final risk score
    result = calculate_risk_score(all_flags)
    print("Step 6 — Risk score calculated")
    
    print("="*45)
    print(f"\n📊 FINAL RESULT:")
    print(f"Risk Score  : {result['score']}")
    print(f"Risk Level  : {result['risk_level']}")
    print(f"Summary     : {result['summary']}")
    
    if verified:
        print(f"\n✅ VERIFIED COMPANIES:")
        for v in verified:
            print(f"   {v['found']} → CIN: {v['cin']}")
    
    if result["flags"]:
        print(f"\n🚨 FLAGS RAISED:")
        for f in result["flags"]:
            print(f"   {f['type']}")
            print(f"   {f['description']}")
            print(f"   Confidence: {f['confidence']}")
    
    return result

# Test with clean document
final_result = analyze_document_v2("sample.pdf")


# In[14]:


def detect_document_type(text):
    text_lower = text.lower()
    
    document_keywords = {
        "salary_slip": [
            "gross salary", "net salary", "basic salary",
            "hra", "provident fund", "salary slip", "payslip"
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
            "built up area", "circle rate", "valuation report", "sq ft"
        ]
    }
    
    scores = {}
    for doc_type, keywords in document_keywords.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        scores[doc_type] = score
    
    detected_type = max(scores, key=scores.get)
    confidence = scores[detected_type] / len(document_keywords[detected_type])
    
    if confidence == 0:
        detected_type = "unknown"
    
    return {
        "document_type": detected_type,
        "confidence": round(confidence, 2),
        "all_scores": scores
    }

# Test it
doc_type = detect_document_type(text)
print(f"Document Type : {doc_type['document_type']}")
print(f"Confidence    : {doc_type['confidence']}")
print(f"\nAll scores:")
for k, v in doc_type['all_scores'].items():
    print(f"  {k}: {v}")


# In[17]:


def validate_pan(text):
    flags = []
    
    # Indian PAN format - 5 letters, 4 digits, 1 letter
    pan_pattern = r'[A-Z]{5}[0-9]{4}[A-Z]{1}'
    
    # Search for PAN in text
    pan_matches = re.findall(pan_pattern, text.upper())
    
    if not pan_matches:
        flags.append({
            "type": "pan_missing",
            "description": "No valid PAN number found in document",
            "confidence": 0.80
        })
    else:
        for pan in pan_matches:
            # 4th character should be entity type
            # P = Individual, C = Company, H = HUF, F = Firm
            entity_type = pan[3]
            valid_entities = ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']
            
            if entity_type not in valid_entities:
                flags.append({
                    "type": "pan_invalid_entity",
                    "description": f"PAN {pan} has invalid entity type '{entity_type}'",
                    "confidence": 0.90
                })
            else:
                print(f"✅ PAN {pan} is valid — Entity type: '{entity_type}'")
    
    return flags

# Test it
pan_flags = validate_pan(text)
if pan_flags:
    for f in pan_flags:
        print(f" {f['type']}: {f['description']}")


# In[20]:


from datetime import datetime
import dateutil.parser

def check_date_consistency(text):
    flags = []
    
    doc = nlp(text)
    
    # Extracting the dates
    dates_found = [ent.text for ent in doc.ents if ent.label_ == "DATE"]
    
    parsed_dates = []
    for date_str in dates_found:
        try:
            parsed = dateutil.parser.parse(date_str, fuzzy=True)
            parsed_dates.append({
                "original": date_str,
                "parsed": parsed
            })
        except:
            pass
    
    # Check 1 — any future dates?
    today = datetime.now()
    for d in parsed_dates:
        if d["parsed"] > today:
            flags.append({
                "type": "future_date",
                "description": f"Document contains a future date: {d['original']}",
                "confidence": 0.85
            })
    
    # Check 2 — dates span more than 1 year?
    if len(parsed_dates) >= 2:
        all_dates = [d["parsed"] for d in parsed_dates]
        date_range = (max(all_dates) - min(all_dates)).days
        if date_range > 365:
            flags.append({
                "type": "date_range_suspicious",
                "description": f"Document dates span {date_range} days — suspicious for a single document",
                "confidence": 0.75
            })
    
    if not flags:
        print(f"Date check passed — {len(parsed_dates)} dates found, all consistent")
    
    return flags, parsed_dates

# Test it
date_flags, dates = check_date_consistency(text)
print(f"\nDates found:")
for d in dates:
    print(f"  {d['original']} → {d['parsed'].strftime('%d %b %Y')}")

if date_flags:
    print(f"\n🚨 DATE FLAGS:")
    for f in date_flags:
        print(f"  {f['type']}: {f['description']}")


# In[21]:


def check_income_vs_profession(text, specific_values):
    flags = []
    
    # Local reference of salary ranges by designation (monthly in INR)
    profession_salary_ranges = {
        "peon": (5000, 20000),
        "clerk": (15000, 40000),
        "assistant": (20000, 60000),
        "officer": (40000, 120000),
        "manager": (60000, 250000),
        "branch manager": (80000, 300000),
        "senior manager": (100000, 400000),
        "deputy manager": (80000, 250000),
        "chief manager": (150000, 500000),
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
    
    # Find designation in text
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
                "confidence": 0.80
            })
        elif gross_salary > max_sal:
            flags.append({
                "type": "income_too_high",
                "description": f"Salary ₹{gross_salary:,.0f} exceeds maximum for {matched_profession} (max: ₹{max_sal:,})",
                "confidence": 0.80
            })
        else:
            print(f"Income check passed — ₹{gross_salary:,.0f} is realistic for {matched_profession}")
    else:
        print(f"Profession not found in reference list — skipping income check")
    
    return flags

# Test it
profession_flags = check_income_vs_profession(text, specific_values)
if profession_flags:
    for f in profession_flags:
        print(f"{f['type']}: {f['description']}")


# In[22]:


def check_ifsc_consistency(text):
    flags = []
    
    # Local reference of bank name to IFSC prefix
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
    
    # Extract IFSC from text
    ifsc_pattern = r'[A-Z]{4}0[A-Z0-9]{6}'
    ifsc_matches = re.findall(ifsc_pattern, text.upper())
    
    text_lower = text.lower()
    
    if not ifsc_matches:
        flags.append({
            "type": "ifsc_missing",
            "description": "No IFSC code found in document",
            "confidence": 0.70
        })
        return flags
    
    for ifsc in ifsc_matches:
        ifsc_prefix = ifsc[:4]
        matched_bank = None
        expected_prefix = None
        
        # Find which bank is mentioned in document
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
                    "confidence": 0.90
                })
            else:
                print(f"IFSC check passed — {ifsc} matches {matched_bank}")
        else:
            print(f"Bank name not found in reference list — skipping IFSC check")
    
    return flags

# Test it
ifsc_flags = check_ifsc_consistency(text)
if ifsc_flags:
    for f in ifsc_flags:
        print(f"{f['type']}: {f['description']}")


# In[28]:


def analyze_document_final_v2(pdf_path):
    print(f"Analyzing: {pdf_path}")
    print("-"*50)
    
    # Step 1 - Extract text
    text = extract_text(pdf_path)
    print("Step 1 - Text extracted")
    
    # Step 2 - Detect document type
    doc_type = detect_document_type(text)
    print(f"Step 2 - Document type detected: {doc_type['document_type']} (confidence: {doc_type['confidence']})")
    
    # Step 3 - Extract financial entities
    financial_data = extract_financial_entities(text)
    print("Step 3 - Financial entities extracted")
    
    # Step 4 - Extract specific values
    specific_values = extract_specific_values(text)
    print("Step 4 - Specific values extracted")
    
    # Step 5 - Run all checks
    print("\nRunning checks...")
    print("-"*50)
    all_flags = []
    
    # Financial inconsistency
    financial_flags = check_inconsistencies_v2(specific_values)
    all_flags.extend(financial_flags)
    
    # Company verification
    verified, company_flags = verify_company_v3(text)
    all_flags.extend(company_flags)
    
    # PAN validation
    pan_flags = validate_pan(text)
    all_flags.extend(pan_flags)
    
    # Date consistency
    date_flags, dates = check_date_consistency(text)
    all_flags.extend(date_flags)
    
    # Income vs profession
    profession_flags = check_income_vs_profession(text, specific_values)
    all_flags.extend(profession_flags)
    
    # IFSC consistency
    ifsc_flags = check_ifsc_consistency(text)
    all_flags.extend(ifsc_flags)
    
    # Step 6 - Calculate final risk score
    result = calculate_risk_score(all_flags)
    
    print("-"*50)
    print("FINAL RESULT")
    print("-"*50)
    print(f"Document Type : {doc_type['document_type']}")
    print(f"Risk Score    : {result['score']}")
    print(f"Risk Level    : {result['risk_level']}")
    print(f"Summary       : {result['summary']}")
    
    if verified:
        print(f"\nVERIFIED COMPANIES:")
        for v in verified:
            print(f"   {v['found']} -> CIN: {v['cin']}")
    
    if result["flags"]:
        print(f"\nFLAGS RAISED:")
        for f in result["flags"]:
            print(f"\n   Type        : {f['type']}")
            print(f"   Description : {f['description']}")
            print(f"   Confidence  : {f['confidence']}")
    else:
        print("\nNo flags raised - document appears genuine")
    
    print("-"*50)
    
    return {
        "document_type": doc_type['document_type'],
        "risk_score": result['score'],
        "risk_level": result['risk_level'],
        "flags": result['flags'],
        "verified_companies": verified
    }

# Test with clean document
final = analyze_document_final_v2("sample.pdf")


# In[26]:


# Simulate a forged document by overriding extracted values
forged_values = {
    "gross_salary": 250000,   # inflated
    "net_salary": 111050,     # unchanged
    "tds": 14500,             # unchanged
    "annual_ctc": 1631400,    # unchanged
    "annual_tds": 174000      # unchanged
}

print("Testing with FORGED document values")
print("="*50)

all_flags = []

# Financial checks on forged values
financial_flags = check_inconsistencies_v2(forged_values)
all_flags.extend(financial_flags)

# Run remaining checks on real text
_, company_flags = verify_company_v3(text)
all_flags.extend(company_flags)

pan_flags = validate_pan(text)
all_flags.extend(pan_flags)

date_flags, _ = check_date_consistency(text)
all_flags.extend(date_flags)

profession_flags = check_income_vs_profession(text, forged_values)
all_flags.extend(profession_flags)

ifsc_flags = check_ifsc_consistency(text)
all_flags.extend(ifsc_flags)

result = calculate_risk_score(all_flags)

print(f"\nFINAL RESULT")
print("="*50)
print(f"Risk Score    : {result['score']}")
print(f"Risk Level    : {result['risk_level']}")
print(f"Summary       : {result['summary']}")

if result["flags"]:
    print(f"\nFLAGS RAISED:")
    for f in result["flags"]:
        print(f"\n   Type       : {f['type']}")
        print(f"   Description: {f['description']}")
        print(f"   Confidence : {f['confidence']}")


# In[ ]:




