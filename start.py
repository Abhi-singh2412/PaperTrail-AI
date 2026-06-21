#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
QUICK START EXAMPLE
Enhanced Document Fraud Detection System
Run this file to see the system in action
"""

import os
import sys
from datetime import datetime

# ============================================================================
# EXAMPLE 1: Single Document Analysis
# ============================================================================

def example_single_document():
    """
    Analyze a single PDF document
    """
    print("\n" + "="*70)
    print("EXAMPLE 1: SINGLE DOCUMENT ANALYSIS")
    print("="*70)
    
    from document_fraud_detector_enhanced import analyze_document
    
    # Replace with your PDF path
    pdf_file = "sample.pdf"
    
    if not os.path.exists(pdf_file):
        print(f"\n❌ File not found: {pdf_file}")
        print("\nTo use this example:")
        print("  1. Place your PDF file in the current directory")
        print("  2. Update pdf_file = 'your_file.pdf'")
        print("  3. Run this script again")
        return
    
    print(f"\nAnalyzing: {pdf_file}")
    print("-" * 70)
    
    # Run analysis
    result = analyze_document(pdf_file)
    
    # Simple result summary
    print("\n✓ Analysis Complete!\n")
    print(f"Risk Level:      {result['risk_level']}")
    print(f"Risk Score:      {result['risk_score']:.2f}/1.00")
    print(f"Credibility:     {result['credibility_score']:.1f}%")
    print(f"Total Issues:    {len(result['flags'])}")
    
    if result['flags']:
        critical = len([f for f in result['flags'] if f['severity'] == 'CRITICAL'])
        high = len([f for f in result['flags'] if f['severity'] == 'HIGH'])
        print(f"Critical:        {critical}")
        print(f"High Severity:   {high}")


# ============================================================================
# EXAMPLE 2: Batch Processing Multiple Documents
# ============================================================================

def example_batch_processing():
    """
    Process multiple PDF documents at once
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: BATCH PROCESSING")
    print("="*70)
    
    from document_fraud_detector_enhanced import analyze_document
    import json
    
    # Directory containing PDFs
    pdf_directory = "./documents"
    
    if not os.path.exists(pdf_directory):
        print(f"\n❌ Directory not found: {pdf_directory}")
        print("\nTo use this example:")
        print("  1. Create a 'documents' folder in current directory")
        print("  2. Place PDF files in it")
        print("  3. Run this script again")
        return
    
    pdf_files = [f for f in os.listdir(pdf_directory) if f.endswith('.pdf')]
    
    if not pdf_files:
        print(f"\n❌ No PDF files found in: {pdf_directory}")
        return
    
    print(f"\nFound {len(pdf_files)} PDF files\n")
    
    results = []
    
    for i, pdf_file in enumerate(pdf_files, 1):
        filepath = os.path.join(pdf_directory, pdf_file)
        print(f"[{i}/{len(pdf_files)}] Processing: {pdf_file}...", end=" ", flush=True)
        
        try:
            result = analyze_document(filepath)
            results.append({
                "file": pdf_file,
                "risk_level": result['risk_level'],
                "risk_score": result['risk_score'],
                "credibility": result['credibility_score'],
                "flags": len(result['flags'])
            })
            print("✓")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    # Print summary
    print("\n" + "-"*70)
    print("BATCH PROCESSING SUMMARY")
    print("-"*70)
    print(f"{'File':<30} {'Risk':<12} {'Score':<8} {'Credibility':<12} {'Issues'}")
    print("-"*70)
    
    for r in results:
        print(f"{r['file']:<30} {r['risk_level']:<12} "
              f"{r['risk_score']:<8.2f} {r['credibility']:<12.1f}% {r['flags']}")
    
    # Save to JSON
    json_output = f"batch_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_output, 'w') as f:
        json.dump({
            "processed_at": datetime.now().isoformat(),
            "total_files": len(results),
            "results": results
        }, f, indent=2)
    
    print(f"\n✓ Results saved to: {json_output}")


# ============================================================================
# EXAMPLE 3: Extract Data Without Risk Analysis
# ============================================================================

def example_data_extraction():
    """
    Extract financial data from PDF without full analysis
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: DATA EXTRACTION ONLY")
    print("="*70)
    
    from document_fraud_detector_enhanced import (
        extract_text,
        extract_specific_values,
        detect_document_type,
        get_pdf_metadata
    )
    import spacy
    
    pdf_file = "sample.pdf"
    
    if not os.path.exists(pdf_file):
        print(f"\n❌ File not found: {pdf_file}")
        return
    
    print(f"\nExtracting data from: {pdf_file}\n")
    
    # Extract text
    text = extract_text(pdf_file)
    print(f"Text extracted: {len(text)} characters")
    
    # Detect document type
    doc_type = detect_document_type(text)
    print(f"Document type: {doc_type['document_type']} "
          f"(confidence: {doc_type['confidence']})")
    
    # Extract financial values
    values, positions = extract_specific_values(text)
    print("\nFinancial Data Found:")
    for key, value in values.items():
        if value is not None:
            if isinstance(value, float):
                print(f"  {key}: ₹{value:,.0f}")
            else:
                print(f"  {key}: {value}")
    
    # Get metadata
    metadata = get_pdf_metadata(pdf_file)
    print("\nPDF Metadata:")
    print(f"  Creator: {metadata.get('creator', 'Unknown')}")
    print(f"  Pages: {metadata.get('pages', 'Unknown')}")
    print(f"  Encrypted: {metadata.get('encrypted', False)}")


# ============================================================================
# EXAMPLE 4: Custom Flag Analysis
# ============================================================================

def example_custom_analysis():
    """
    Perform custom analysis on specific checks
    """
    print("\n" + "="*70)
    print("EXAMPLE 4: CUSTOM ANALYSIS")
    print("="*70)
    
    from document_fraud_detector_enhanced import (
        extract_text,
        extract_specific_values,
        check_inconsistencies,
        validate_pan,
        check_ifsc_consistency,
        load_nlp_model,
        check_date_consistency
    )
    
    pdf_file = "sample.pdf"
    
    if not os.path.exists(pdf_file):
        print(f"\n❌ File not found: {pdf_file}")
        return
    
    print(f"\nRunning custom checks on: {pdf_file}\n")
    
    # Load resources
    nlp = load_nlp_model()
    text = extract_text(pdf_file)
    values, _ = extract_specific_values(text)
    
    # Run specific checks
    print("1. FINANCIAL CONSISTENCY CHECKS")
    print("-" * 70)
    financial_flags = check_inconsistencies(values)
    if financial_flags:
        for flag in financial_flags:
            print(f"  ⚠️  {flag['type']}: {flag['description']}")
    else:
        print("  ✓ No financial inconsistencies found")
    
    print("\n2. PAN VALIDATION")
    print("-" * 70)
    pan_flags = validate_pan(text)
    if pan_flags:
        for flag in pan_flags:
            print(f"  ⚠️  {flag['description']}")
    else:
        print("  ✓ PAN validation passed")
    
    print("\n3. IFSC CODE VALIDATION")
    print("-" * 70)
    ifsc_flags = check_ifsc_consistency(text)
    if ifsc_flags:
        for flag in ifsc_flags:
            print(f"  ⚠️  {flag['description']}")
    else:
        print("  ✓ IFSC validation passed")
    
    print("\n4. DATE CONSISTENCY")
    print("-" * 70)
    date_flags, dates = check_date_consistency(text, nlp)
    if dates:
        print(f"  Found {len(dates)} dates:")
        for d in dates:
            print(f"    • {d['original']}")
    if date_flags:
        for flag in date_flags:
            print(f"  ⚠️  {flag['description']}")
    else:
        print("  ✓ Date validation passed")


# ============================================================================
# EXAMPLE 5: Compare Results Across Documents
# ============================================================================

def example_comparison():
    """
    Compare analysis results across multiple documents
    """
    print("\n" + "="*70)
    print("EXAMPLE 5: DOCUMENT COMPARISON")
    print("="*70)
    
    from document_fraud_detector_enhanced import analyze_document
    
    # This example shows how to compare two documents
    docs = ["salary_2023.pdf", "salary_2024.pdf"]
    
    # Check if files exist
    missing = [d for d in docs if not os.path.exists(d)]
    if missing:
        print(f"\n❌ Missing files: {missing}")
        print("\nTo use this example:")
        print("  1. Have two salary slip PDFs")
        print("  2. Name them 'salary_2023.pdf' and 'salary_2024.pdf'")
        print("  3. Run this script again")
        return
    
    print(f"\nComparing documents: {docs[0]} vs {docs[1]}\n")
    
    results = {}
    
    for pdf_file in docs:
        result = analyze_document(pdf_file)
        results[pdf_file] = {
            "risk_level": result['risk_level'],
            "risk_score": result['risk_score'],
            "credibility": result['credibility_score'],
            "flags": len(result['flags']),
            "financial_data": result['financial_data']
        }
    
    # Comparison display
    print("\nCOMPARISON RESULTS")
    print("-" * 70)
    print(f"{'Metric':<25} {docs[0]:<25} {docs[1]:<25}")
    print("-" * 70)
    
    r1, r2 = results[docs[0]], results[docs[1]]
    
    print(f"{'Risk Level':<25} {r1['risk_level']:<25} {r2['risk_level']:<25}")
    print(f"{'Risk Score':<25} {r1['risk_score']:<25.2f} {r2['risk_score']:<25.2f}")
    print(f"{'Credibility':<25} {r1['credibility']:<25.1f}% {r2['credibility']:<24.1f}%")
    print(f"{'Total Flags':<25} {r1['flags']:<25} {r2['flags']:<25}")
    
    # Salary comparison
    if r1['financial_data'].get('gross_salary') and r2['financial_data'].get('gross_salary'):
        sal1 = r1['financial_data']['gross_salary']
        sal2 = r2['financial_data']['gross_salary']
        increase = ((sal2 - sal1) / sal1) * 100
        
        print(f"\n{'Gross Salary':<25} ₹{sal1:<24,.0f} ₹{sal2:<24,.0f}")
        print(f"{'Salary Increase':<25} {increase:.1f}%")


# ============================================================================
# MENU SYSTEM
# ============================================================================

def main():
    """
    Interactive menu for examples
    """
    print("\n" + "="*70)
    print("ENHANCED DOCUMENT FRAUD DETECTION SYSTEM")
    print("Quick Start Examples")
    print("="*70)
    
    examples = {
        "1": ("Single Document Analysis", example_single_document),
        "2": ("Batch Processing", example_batch_processing),
        "3": ("Data Extraction Only", example_data_extraction),
        "4": ("Custom Analysis", example_custom_analysis),
        "5": ("Document Comparison", example_comparison),
        "0": ("Exit", None)
    }
    
    while True:
        print("\nAvailable Examples:")
        for key, (name, _) in examples.items():
            if key != "0":
                print(f"  {key}. {name}")
            else:
                print(f"  {key}. {name}")
        
        choice = input("\nSelect example (0-5): ").strip()
        
        if choice not in examples:
            print("❌ Invalid choice. Please try again.")
            continue
        
        if choice == "0":
            print("\nThank you for using the system!")
            break
        
        name, func = examples[choice]
        print(f"\n>>> Running: {name}")
        
        try:
            func()
        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("\nMake sure:")
            print("  • All dependencies are installed")
            print("  • PDF files exist at specified paths")
            print("  • spaCy model is downloaded: python -m spacy download en_core_web_sm")
        
        input("\n[Press Enter to continue...]")


if __name__ == "__main__":
    # Check if dependencies are installed
    try:
        import fitz
        import spacy
        import dateutil
        print("\n✓ All dependencies found!")
    except ImportError as e:
        print(f"\n❌ Missing dependency: {e}")
        print("\nInstall required packages:")
        print("  pip install pymupdf spacy python-dateutil")
        print("  python -m spacy download en_core_web_sm")
        sys.exit(1)
    
    # Run menu
    main()