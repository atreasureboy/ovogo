#!/usr/bin/env python3
"""
Intentionally vulnerable Flask app for ovogo end-to-end kill chain tests.

Vulnerabilities (deliberately, for authorized testing only):
  1. SQL injection on GET /api/users?id= → leaks `flag` column from users table
  2. Command injection on GET /api/ping?host= → RCE (writes to /tmp/owned.txt)
  3. Path traversal on GET /api/file?name= → reads arbitrary file
  4. Reflected XSS on GET /search?q= → for completeness

The DB is created in-memory on startup with a single users row containing
a known flag. The goal of the e2e test is to:
  1. Probe /api/users and find SQLi
  2. Generate SQLi payload via PayloadGenerator
  3. Execute payload via Bash tool
  4. Assert flag appears in response

Run standalone:
  python3 tests/e2e/target/app.py [port]
"""
import sys
import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify

FLAG = os.environ.get('E2E_FLAG', 'flag{ovogo_e2e_pwned_2026}')
DB_PATH = '/tmp/e2e_target.db'

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        os.unlink(DB_PATH)
    conn = db()
    conn.execute(
        'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, flag TEXT)'
    )
    conn.execute(
        "INSERT INTO users (username, password, role, flag) VALUES "
        "('admin', 'admin123', 'admin', ?), "
        "('guest', 'guest', 'user', NULL)",
        (FLAG,),
    )
    conn.commit()
    conn.close()


@app.route('/')
def root():
    return jsonify({
        'app': 'ovogo-e2e-vuln-target',
        'endpoints': [
            'GET /api/users?id=<int>      # INTENDED (but SQLi works)',
            'GET /api/ping?host=<host>    # INTENDED (but cmdi works)',
            'GET /api/file?name=<path>    # INTENDED (but LFI works)',
            'GET /search?q=<query>        # XSS reflects q',
            'GET /flag                    # Just returns the flag (sanity)',
        ],
        'flag_hint': 'SQLi on /api/users leaks the flag column from row id=1',
    })


@app.route('/flag')
def flag_route():
    return jsonify({'flag': FLAG})


# ── Vulnerability #1: SQL injection on /api/users?id= ─────────────────────
@app.route('/api/users')
def api_users():
    uid = request.args.get('id', '1')
    # DELIBERATELY vulnerable — string concat, no param binding
    conn = db()
    try:
        rows = conn.execute(f"SELECT id, username, password, role, flag FROM users WHERE id = {uid}").fetchall()
    except Exception as e:
        return jsonify({'error': str(e), 'sql_attempted': f'SELECT ... WHERE id = {uid}'}), 500
    return jsonify([dict(r) for r in rows])


# ── Vulnerability #2: command injection on /api/ping?host= ───────────────
@app.route('/api/ping')
def api_ping():
    host = request.args.get('host', '127.0.0.1')
    # DELIBERATELY vulnerable — shell=True with user input
    try:
        out = subprocess.check_output(f'ping -c 1 -W 1 {host}', shell=True, stderr=subprocess.STDOUT, timeout=3)
        return jsonify({'output': out.decode(errors='ignore')[:500]})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'timeout'}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output.decode(errors='ignore')[:500]}), 500


# ── Vulnerability #3: path traversal on /api/file?name= ───────────────────
@app.route('/api/file')
def api_file():
    name = request.args.get('name', 'app.py')
    # DELIBERATELY vulnerable — no path sanitization
    base = os.path.dirname(os.path.abspath(__file__))
    try:
        path = os.path.join(base, name)
        with open(path, 'r') as f:
            return jsonify({'content': f.read()[:2000]})
    except Exception as e:
        return jsonify({'error': str(e), 'attempted_path': name}), 500


# ── Vulnerability #4: reflected XSS on /search?q= (for completeness) ──────
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Reflected unsanitized
    return f'<html><body>Search results for: {q}</body></html>'


if __name__ == '__main__':
    init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)