#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Document Fraud Detection System - Flask Web Server
Main entry point
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import json
import traceback
from datetime import datetime
import tempfile
import shutil

app = Flask(__name__, static_folder='static')
CORS(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), 'outputs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Serve the frontend
# ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)


# ──────────────────────────────────────────────────────────────
# Upload endpoint
# ──────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'Only PDF files are supported'}), 400

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = f"doc_{timestamp}.pdf"
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(save_path)

    return jsonify({
        'success': True,
        'filename': safe_name,
        'original_name': f.filename,
        'size_kb': round(os.path.getsize(save_path) / 1024, 1)
    })


# ──────────────────────────────────────────────────────────────
# Cyber Check endpoint
# ──────────────────────────────────────────────────────────────

@app.route('/analyze/cyber', methods=['POST'])
def analyze_cyber():
    data = request.get_json()
    filename = data.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(pdf_path):
        return jsonify({'error': 'File not found'}), 404

    try:
        from cyber_detector_module import run_cyber_analysis
        result = run_cyber_analysis(pdf_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500


# ──────────────────────────────────────────────────────────────
# Content / Fraud Check endpoint
# ──────────────────────────────────────────────────────────────

@app.route('/analyze/fraud', methods=['POST'])
def analyze_fraud():
    data = request.get_json()
    filename = data.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(pdf_path):
        return jsonify({'error': 'File not found'}), 404

    try:
        from fraud_detector_module import run_fraud_analysis
        result = run_fraud_analysis(pdf_path, OUTPUT_FOLDER)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500


# ──────────────────────────────────────────────────────────────
# Download annotated PDF
# ──────────────────────────────────────────────────────────────

@app.route('/download/<path:filename>')
def download(filename):
    # Security: only serve from outputs folder
    safe_path = os.path.join(OUTPUT_FOLDER, os.path.basename(filename))
    if not os.path.exists(safe_path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(safe_path, as_attachment=True, download_name=os.path.basename(filename))


# ──────────────────────────────────────────────────────────────
# Download full JSON report
# ──────────────────────────────────────────────────────────────

@app.route('/report', methods=['POST'])
def download_report():
    data = request.get_json()
    cyber = data.get('cyber', {})
    fraud = data.get('fraud', {})
    filename = data.get('filename', 'document')

    report = {
        'generated_at': datetime.now().isoformat(),
        'document': filename,
        'cyber_analysis': cyber,
        'fraud_analysis': fraud
    }

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_name = f"report_{timestamp}.json"
    report_path = os.path.join(OUTPUT_FOLDER, report_name)
    with open(report_path, 'w') as fp:
        json.dump(report, fp, indent=2, default=str)

    return send_file(report_path, as_attachment=True, download_name=report_name)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Document Fraud Detection System")
    print("  Open: http://localhost:5000")
    print("="*60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')