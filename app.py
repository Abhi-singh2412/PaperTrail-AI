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

from flask import Flask, request, jsonify, send_file, send_from_directory, session
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
from pypdf import PdfReader, PdfWriter
import os
import json
import hashlib
import hmac
import secrets
import string
import traceback
from datetime import datetime

load_dotenv()  # reads a .env file in the project root, if present

app = Flask(__name__, static_folder='static')

# IMPORTANT: this must stay the SAME value across server restarts, or every
# existing session cookie becomes invalid the instant the server reloads
# (which Flask's debug mode does constantly). A random fallback that
# regenerates on every restart is exactly what was silently breaking
# "logged in" state -> uploads/analysis would 401 internally, but the
# frontend showed no annotated PDF / no stats with no visible error.
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not FLASK_SECRET_KEY:
    raise RuntimeError(
        'Missing FLASK_SECRET_KEY environment variable. Set it to any '
        'long random string and keep it the same across restarts, e.g.\n'
        '  FLASK_SECRET_KEY=' + secrets.token_hex(32) + '\n'
        '(generated just now — copy it into your .env file)'
    )
app.secret_key = FLASK_SECRET_KEY

# Session cookie behaves on plain http://localhost during development.
# If you deploy behind https in production, set SESSION_COOKIE_SECURE=true.
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

# Explicit origin (not "*") is required for the browser to accept a
# credentialed (cookie-carrying) request at all -- this is a CORS spec
# rule, not a Flask quirk. Adjust ALLOWED_ORIGIN if you serve the
# frontend from a different host/port than the Flask app itself.
ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
CORS(app, supports_credentials=True, origins=[ALLOWED_ORIGIN])

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
# Document storage (Supabase Storage + documents table)
# ──────────────────────────────────────────────────────────────

ORIGINAL_BUCKET = 'original-pdfs'
ANNOTATED_BUCKET = 'annotated-pdfs'


def _ensure_buckets():
    """Create the two storage buckets if they don't exist yet. Private —
    files are not reachable by a public URL; access goes through the
    secret key on the server."""
    try:
        existing = {b.name for b in supabase.storage.list_buckets()}
    except Exception:
        existing = set()
    for bucket in (ORIGINAL_BUCKET, ANNOTATED_BUCKET):
        if bucket not in existing:
            try:
                supabase.storage.create_bucket(
                    bucket,
                    options={'public': False}
                )
            except Exception:
                pass  # likely already exists or a race with another worker


_ensure_buckets()


def _upload_to_storage(bucket, storage_path, local_path):
    """Upload a local file to a Supabase Storage bucket. Returns the
    storage path on success, None on failure (caller decides how to react)."""
    try:
        with open(local_path, 'rb') as f:
            file_bytes = f.read()
        supabase.storage.from_(bucket).upload(
            storage_path,
            file_bytes,
            {'content-type': 'application/pdf'}
        )
        return storage_path
    except Exception as e:
        print(f"[storage] upload failed for {bucket}/{storage_path}: {e}")
        return None


def _save_document_record(user_email, original_filename,
                           original_storage_path, annotated_storage_path,
                           cyber_result, fraud_result, pdf_password=None):
    risk_level = (fraud_result or {}).get('risk_level') or (cyber_result or {}).get('risk_level') or 'UNKNOWN'
    credibility = (fraud_result or {}).get('credibility_score')
    try:
        supabase.table('documents').insert({
            'user_email': user_email,
            'original_filename': original_filename,
            'original_storage_path': original_storage_path,
            'annotated_storage_path': annotated_storage_path,
            'pdf_password': pdf_password,
            'risk_level': risk_level,
            'credibility_score': credibility,
            'cyber_result': cyber_result,
            'fraud_result': fraud_result,
        }).execute()
    except Exception as e:
        print(f"[db] failed to save document record: {e}")


# ──────────────────────────────────────────────────────────────
# PDF password protection
# ──────────────────────────────────────────────────────────────
# The annotated PDF is encrypted with a random password BEFORE it is
# uploaded to Supabase Storage, so the file sitting in Storage is
# protected even if someone downloads it directly from the Supabase
# dashboard or grabs the raw URL -- not just when going through this
# app's own /download route.
#
# The password is generated fresh per document, shown to the user once
# in the analysis response (so the frontend can display it), and saved
# in the documents table so it can be re-shown if the user revisits an
# old scan. It is NEVER derived from or related to the user's login
# password -- using a login credential to encrypt a file that may end
# up shared or stored elsewhere would let that file leak the password
# used to access the account itself.

PDF_PASSWORD_LENGTH = 10
PDF_PASSWORD_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


def _generate_pdf_password():
    return ''.join(secrets.choice(PDF_PASSWORD_ALPHABET) for _ in range(PDF_PASSWORD_LENGTH))


def _encrypt_pdf_in_place(pdf_path, password):
    """Encrypts the PDF at pdf_path with the given password, overwriting it.
    Returns True on success, False on failure (caller decides how to react)."""
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # user_password: required to open/view the PDF at all.
        # owner_password: a separate, stronger random secret that grants full
        # permissions (printing, editing). We set it too, rather than reusing
        # the same value, because pypdf disallows an empty owner password.
        owner_password = secrets.token_hex(16)
        writer.encrypt(user_password=password, owner_password=owner_password)
        with open(pdf_path, 'wb') as f:
            writer.write(f)
        return True
    except Exception as e:
        print(f"[pdf] encryption failed for {pdf_path}: {e}")
        return False

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

    session['user_email'] = email
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

    session['user_email'] = email
    return jsonify({'ok': True, 'email': email})


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email', None)
    return jsonify({'ok': True})


@app.route('/me')
def me():
    """Lets the frontend check who's logged in (or get a 401 if no one is)."""
    email = session.get('user_email')
    if not email:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'email': email})


# ──────────────────────────────────────────────────────────────
# Upload endpoint
# ──────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({'error': 'Please log in first.'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'Only PDF files are supported'}), 400

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = f"doc_{timestamp}.pdf"
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(save_path)

    # Mirror the original PDF into Supabase Storage, namespaced by user email
    # so each user's files live in their own "folder" inside the bucket.
    storage_path = f"{user_email}/{safe_name}"
    _upload_to_storage(ORIGINAL_BUCKET, storage_path, save_path)

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
    if not session.get('user_email'):
        return jsonify({'error': 'Please log in first.'}), 401

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
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({'error': 'Please log in first.'}), 401

    data = request.get_json()
    filename = data.get('filename')
    cyber_result = data.get('cyber_result')  # optional, passed from frontend if available
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(pdf_path):
        return jsonify({'error': 'File not found'}), 404

    try:
        from fraud_detector_module import run_fraud_analysis
        result = run_fraud_analysis(pdf_path, OUTPUT_FOLDER)
    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

    # Push the annotated PDF (if one was generated) to Supabase Storage,
    # encrypted with a freshly generated random password, and record this
    # scan in the documents table.
    annotated_storage_path = None
    pdf_password = None
    annotated_name = result.get('annotated_pdf')
    if annotated_name:
        annotated_local_path = os.path.join(OUTPUT_FOLDER, annotated_name)
        if os.path.exists(annotated_local_path):
            pdf_password = _generate_pdf_password()
            encrypted_ok = _encrypt_pdf_in_place(annotated_local_path, pdf_password)
            if not encrypted_ok:
                # Don't silently hand back an unprotected file -- surface it.
                pdf_password = None
            annotated_storage_path = f"{user_email}/{annotated_name}"
            _upload_to_storage(ANNOTATED_BUCKET, annotated_storage_path, annotated_local_path)

    original_storage_path = f"{user_email}/{filename}"
    _save_document_record(
        user_email=user_email,
        original_filename=filename,
        original_storage_path=original_storage_path,
        annotated_storage_path=annotated_storage_path,
        cyber_result=cyber_result,
        fraud_result=result,
        pdf_password=pdf_password,
    )

    # Shown once to the user right after analysis completes. The frontend
    # is responsible for displaying this clearly and noting it won't be
    # shown again automatically (it CAN be looked up again via the
    # documents table / a "show password" action if you build one).
    result['pdf_password'] = pdf_password

    return jsonify(result)


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
    # use_reloader=False: the auto-reloader watches every imported .py file
    # (including deep into torch's internals) and restarts the whole server
    # the instant any of them gets touched -- which happens the first time
    # fraud_detector_module imports torch / an NLP model. That restart kills
    # the in-flight /analyze/fraud request, which is why the browser saw
    # "failed to fetch" right as that request started. debug=True still
    # gives you full tracebacks in the browser; only the file-watching
    # auto-restart is disabled.
    app.run(debug=True, use_reloader=False, port=5000, host='0.0.0.0')