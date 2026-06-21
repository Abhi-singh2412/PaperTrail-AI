#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CONFIGURATION TEMPLATE
Customize the Document Fraud Detection System for your specific needs
"""

# ============================================================================
# FINANCIAL THRESHOLDS
# ============================================================================

FINANCIAL_CONFIG = {
    "tds_percentage": {
        "min": 5,
        "max": 30,
        "description": "Expected TDS as percentage of Annual CTC"
    },
    "salary_deduction_percentage": {
        "min": 5,
        "max": 50,
        "description": "Expected deductions as percentage of gross salary"
    },
    "annual_ctc_variance": {
        "max_percent_diff": 20,
        "description": "Max allowed difference between CTC and Gross×12"
    }
}


# ============================================================================
# PROFESSION SALARY RANGES (Monthly, in INR)
# ============================================================================

PROFESSION_SALARY_RANGES = {
    # Administrative roles
    "peon": (5000, 20000),
    "clerk": (15000, 40000),
    "assistant": (20000, 60000),
    "receptionist": (12000, 35000),
    "secretary": (20000, 50000),
    
    # Banking roles
    "officer": (40000, 120000),
    "manager": (60000, 250000),
    "branch manager": (80000, 300000),
    "senior manager": (100000, 400000),
    "deputy manager": (80000, 250000),
    "chief manager": (150000, 500000),
    
    # IT roles
    "engineer": (30000, 200000),
    "software engineer": (50000, 300000),
    "senior engineer": (80000, 400000),
    "analyst": (40000, 200000),
    "consultant": (60000, 400000),
    "developer": (40000, 250000),
    "lead developer": (70000, 350000),
    
    # Finance roles
    "accountant": (20000, 80000),
    "senior accountant": (40000, 120000),
    "financial analyst": (30000, 150000),
    "cfo": (150000, 1000000),
    
    # Education roles
    "teacher": (20000, 80000),
    "professor": (50000, 150000),
    "principal": (80000, 200000),
    
    # Healthcare roles
    "doctor": (50000, 300000),
    "surgeon": (100000, 500000),
    "nurse": (20000, 60000),
    "pharmacist": (25000, 100000),
    
    # Legal roles
    "lawyer": (50000, 500000),
    "advocate": (40000, 400000),
    "paralegal": (20000, 60000),
}

# Add your custom professions here:
CUSTOM_PROFESSION_RANGES = {
    # Example:
    # "your_job": (min_salary, max_salary),
}

PROFESSION_SALARY_RANGES.update(CUSTOM_PROFESSION_RANGES)


# ============================================================================
# COMPANY WHITELIST (CIN - Corporate Identification Number)
# ============================================================================

COMPANY_WHITELIST = {
    # Banks
    "Canara Bank Ltd": "L85110KA1969GOI001856",
    "State Bank of India": "L64190MH1955GOI008712",
    "HDFC Bank Ltd": "L65920MH1994PLC080618",
    "ICICI Bank Ltd": "L65190GJ1994PLC021012",
    "Axis Bank": "L65110GJ2007PLC079808",
    "Punjab National Bank": "L65190PB1894GOI000030",
    "Bank of Baroda": "L75190GJ1952GOI000001",
    "Union Bank of India": "L65190MH1919GOI000105",
    
    # IT Companies
    "Infosys Ltd": "L85110KA1981PLC013115",
    "Tata Consultancy Services": "L22210MH1995PLC084781",
    "Wipro Ltd": "L32102KA1945PLC020800",
    "HCL Technologies": "L72200UP1999PLC023008",
    "Tech Mahindra": "L32200MH1986PLC041957",
    "Cognizant": "L72100MH1994PLC086387",
    "Accenture India": "L85110KA1989PLC020234",
    
    # Financial Services
    "Reliance Industries Ltd": "L17110MH1973PLC019786",
    "HDFC": "L65191MH1977PLC019916",
    "ICICI Lombard": "L67200MH2000PLC129408",
    "Bajaj Auto": "L74899MH1926PLC000050",
    
    # Pharmaceuticals
    "Dr. Reddy's Laboratories": "L73100AP1984PLC037913",
    "Cipla Limited": "L65110MH1935PLC002380",
    "Lupin Limited": "L24239MH1968PLC013803",
    
    # Retail/Ecommerce
    "Amazon India": "U51109UP2013FTC056994",
    "Flipkart": "U51109TG2012FTC081857",
    "Walmart": "U45309TN2019PLC125223",
}

# Add your custom companies here:
CUSTOM_WHITELIST = {
    # Example:
    # "Your Company": "CIN_CODE_HERE",
}

COMPANY_WHITELIST.update(CUSTOM_WHITELIST)


# ============================================================================
# BANK TO IFSC CODE MAPPING
# ============================================================================

BANK_IFSC_MAP = {
    # Nationalized Banks
    "canara bank": "CNRB",
    "state bank of india": "SBIN",
    "bank of baroda": "BARB",
    "union bank": "UBIN",
    "indian bank": "IDIB",
    "central bank": "CBIN",
    "bank of india": "BKID",
    "punjab national bank": "PUNB",
    
    # Private Banks
    "hdfc bank": "HDFC",
    "icici bank": "ICIC",
    "axis bank": "UTIB",
    "kotak mahindra bank": "KKBK",
    "yes bank": "YESB",
    "idbi bank": "IBKL",
    "bsnl": "BKSL",
    
    # HSBC and others
    "hsbc": "HSBC",
    "deutsche bank": "DEUT",
    "standard chartered": "SCBL",
    "citibank": "CITI",
}

# Add your custom banks here:
CUSTOM_BANKS = {
    # Example:
    # "your_bank": "IFSC_PREFIX",
}

BANK_IFSC_MAP.update(CUSTOM_BANKS)


# ============================================================================
# RISK SCORING WEIGHTS
# ============================================================================

RISK_WEIGHTS = {
    "critical_flag_weight": 0.5,      # Each critical flag adds 0.5 to score
    "high_flag_weight": 0.25,         # Each high severity flag adds 0.25
    "medium_flag_weight": 0.1,        # Each medium flag adds 0.1
    "low_flag_weight": 0.05,          # Each low flag adds 0.05
}

RISK_THRESHOLDS = {
    "critical": 0.70,                 # Risk score >= 0.70
    "high": 0.50,                     # 0.50 to 0.69
    "medium": 0.25,                   # 0.25 to 0.49
    "low": 0.0                        # < 0.25
}


# ============================================================================
# CREDIBILITY SCORING WEIGHTS
# ============================================================================

CREDIBILITY_WEIGHTS = {
    "financial_completeness": 25,     # Out of 100 points
    "metadata_quality": 15,
    "company_verification": 20,
    "pan_validation": 15,
    "document_type_confidence": 10,
    "ifsc_code": 15,
    # Total: 100 points
}


# ============================================================================
# SEVERITY LEVELS
# ============================================================================

SEVERITY_LEVELS = {
    "CRITICAL": {
        "color": (1, 0, 0),           # Red in PDF
        "requires_rejection": True,
        "description": "Clear signs of forgery"
    },
    "HIGH": {
        "color": (1, 0.5, 0),         # Orange in PDF
        "requires_review": True,
        "description": "Multiple issues detected"
    },
    "MEDIUM": {
        "color": (1, 1, 0),           # Yellow in PDF
        "requires_caution": True,
        "description": "Some inconsistencies"
    },
    "LOW": {
        "color": (0, 0.5, 1),         # Light Blue in PDF
        "requires_note": True,
        "description": "Minor issues"
    }
}


# ============================================================================
# DOCUMENT TYPE KEYWORDS
# ============================================================================

DOCUMENT_TYPE_KEYWORDS = {
    "salary_slip": [
        "gross salary", "net salary", "basic salary",
        "hra", "provident fund", "salary slip", "payslip",
        "employee", "monthly", "deduction", "allowance"
    ],
    "form_16": [
        "form 16", "tds certificate", "assessment year",
        "total income", "deductions under chapter",
        "part a", "part b", "verification", "employer"
    ],
    "bank_statement": [
        "account statement", "opening balance", "closing balance",
        "transaction date", "debit", "credit", "balance brought forward",
        "account number", "ifsc", "branch"
    ],
    "itr": [
        "income tax return", "assessment year", "gross total income",
        "tax payable", "schedule", "itr-1", "itr-2",
        "verification", "return filed", "aaykar"
    ],
    "property_valuation": [
        "property valuation", "market value", "plot area",
        "built up area", "circle rate", "valuation report",
        "sq ft", "depreciation", "fair value"
    ]
}


# ============================================================================
# PAN CONFIGURATION
# ============================================================================

PAN_CONFIG = {
    "valid_entity_types": ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'],
    "entity_type_mapping": {
        'P': 'Individual',
        'C': 'Company',
        'H': 'HUF (Hindu Undivided Family)',
        'F': 'Firm',
        'A': 'AOP (Association of Persons)',
        'T': 'Trust',
        'B': 'Body of Individuals',
        'L': 'Local Authority',
        'J': 'Juridical Person',
        'G': 'Government'
    },
    "pattern": r"[A-Z]{5}[0-9]{4}[A-Z]{1}"
}


# ============================================================================
# IFSC CONFIGURATION
# ============================================================================

IFSC_CONFIG = {
    "pattern": r"[A-Z]{4}0[A-Z0-9]{6}",
    "format_description": "XXXX0XXXXXX where X = letter or digit",
    "length": 11
}


# ============================================================================
# REPORT SETTINGS
# ============================================================================

REPORT_SETTINGS = {
    "include_metadata": True,
    "include_entities": True,
    "include_financial_data": True,
    "include_raw_flags": True,
    "json_indent": 2,
    "show_confidence_scores": True,
    "annotation_colors": True,
    "detailed_output": True
}


# ============================================================================
# PROCESSING SETTINGS
# ============================================================================

PROCESSING_CONFIG = {
    "max_pdf_size_mb": 100,
    "nlp_batch_size": 1,
    "timeout_seconds": 30,
    "extract_images": False,
    "extract_tables": False,
    "preserve_formatting": False
}


# ============================================================================
# PDF ANNOTATION SETTINGS
# ============================================================================

PDF_ANNOTATION_CONFIG = {
    "create_annotated_copy": True,
    "add_watermark": False,
    "font_size": 10,
    "highlight_style": "boxes",  # or "highlight", "underline"
    "color_code_by_severity": True,
    "add_page_numbers": True,
    "add_timestamp": True
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_company_cin(company_name):
    """Lookup CIN for a company"""
    return COMPANY_WHITELIST.get(company_name, None)


def get_bank_ifsc_prefix(bank_name):
    """Get IFSC prefix for a bank"""
    return BANK_IFSC_MAP.get(bank_name.lower(), None)


def get_profession_salary_range(profession):
    """Get expected salary range for a profession"""
    return PROFESSION_SALARY_RANGES.get(profession.lower(), None)


def get_risk_threshold(risk_level):
    """Get score threshold for a risk level"""
    return RISK_THRESHOLDS.get(risk_level, None)


def get_severity_info(severity):
    """Get information about a severity level"""
    return SEVERITY_LEVELS.get(severity, None)


# ============================================================================
# EXPORT FOR USE IN MAIN SYSTEM
# ============================================================================

if __name__ == "__main__":
    print("Configuration Template Loaded")
    print("\nTo use custom configuration:")
    print("1. Update the dictionaries above with your values")
    print("2. Import in main script: from config import COMPANY_WHITELIST")
    print("3. Use in functions: company = COMPANY_WHITELIST.get(name)")
    
    # Display summary
    print("\n" + "="*70)
    print("CONFIGURATION SUMMARY")
    print("="*70)
    print(f"Companies in Whitelist: {len(COMPANY_WHITELIST)}")
    print(f"Banks Mapped: {len(BANK_IFSC_MAP)}")
    print(f"Professions Defined: {len(PROFESSION_SALARY_RANGES)}")
    print(f"Document Types: {len(DOCUMENT_TYPE_KEYWORDS)}")
    print(f"Severity Levels: {len(SEVERITY_LEVELS)}")