#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Document Fraud Detection System - Flask Web Server
Main entry point

Flow:
  /            -> landing.html (login / sign up)
  /signup      -> POST, creates a user row in Supabase (public.users)
  /login       -> POST, checks credentials against Supabase
  /index.html  -> the DocShield console (static/index.html) — the page
                  the landing page redirects to after a successful
                  login or signup

Requires SUPABASE_URL and SUPABASE_SECRET_KEY environment variables.
See supabase_setup.sql for the one-time table setup.
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import json
import hashlib
import hmac
import secrets
import traceback
from datetime import datetime

load_dotenv()  # reads a .env file in the project root, if present

app = Flask(__name__, static_folder='static')
CORS(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), 'outputs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Auth storage (Supabase)
# ──────────────────────────────────────────────────────────────
# Set these two as environment variables before running the app:
#   SUPABASE_URL       -> Project URL, e.g. https://xxxxx.supabase.co
#   SUPABASE_SECRET_KEY -> the "secret" key (sb_secret_...) from
#                          Settings > API Keys. NEVER the publishable/anon
#                          key — this key bypasses Row Level Security so
#                          the server can read/write the users table.
#
# Example (macOS/Linux):
#   export SUPABASE_URL="https://xxxxx.supabase.co"
#   export SUPABASE_SECRET_KEY="sb_secret_xxx..."
#
# Run the SQL in supabase_setup.sql once in the Supabase SQL Editor
# before starting the app, to create the `users` table.

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_SECRET_KEY = os.environ.get('SUPABASE_SECRET_KEY')

if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        'Missing SUPABASE_URL or SUPABASE_SECRET_KEY environment variables. '
        'Set them before starting the app (see comments above this check).'
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)


def _hash_password(password, salt=None):
    """PBKDF2 hash so plaintext passwords never touch the database."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000
    )
    return digest.hex(), salt


def _find_user(email):
    """Look up a user row by email (case-insensitive)."""
    result = (
        supabase.table('users')
        .select('email, password_hash, salt')
        .eq('email', email.lower())
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


def _create_user(email, password_hash, salt):
    supabase.table('users').insert({
        'email': email,
        'password_hash': password_hash,
        'salt': salt,
    }).execute()

# ──────────────────────────────────────────────────────────────
# Serve the frontend
# ──────────────────────────────────────────────────────────────

@app.route('/')
def landing():
    # Landing page (login / sign up) is now the front door
    return send_from_directory('static', 'landing.html')


@app.route('/index.html')
def index():
    # The DocShield console — reached after a successful login/signup
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)


# ──────────────────────────────────────────────────────────────
# Auth endpoints
# ──────────────────────────────────────────────────────────────

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or '@' not in email:
        return jsonify({'error': 'Please enter a valid email.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    if _find_user(email):
        return jsonify({'error': 'An account with that email already exists.'}), 409

    pw_hash, salt = _hash_password(password)
    try:
        _create_user(email, pw_hash, salt)
    except Exception as e:
        # Most likely a race on the unique email index, or a connection issue
        return jsonify({'error': 'Could not create account. Please try again.'}), 500

    return jsonify({'ok': True, 'email': email})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    user = _find_user(email)
    if not user:
        return jsonify({'error': 'No account found with that email.'}), 404

    check_hash, _ = _hash_password(password, salt=user['salt'])
    if not hmac.compare_digest(check_hash, user['password_hash']):
        return jsonify({'error': 'Incorrect password.'}), 401

    return jsonify({'ok': True, 'email': email})


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