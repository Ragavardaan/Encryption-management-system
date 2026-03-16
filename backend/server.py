import os
import hashlib
import sqlite3
import logging
import traceback
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort, Blueprint
from flask_cors import CORS
from werkzeug.utils import secure_filename
import mysql.connector

# Project-specific modules, keep these as needed
import symmetric
import asymmetric
import key_exchange
import resources
from file_encrypt import encrypt_content, decrypt_content

# --- App setup ---
app = Flask(__name__)
CORS(app, supports_credentials=True)
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# --- Config ---
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'mysql-atlb.railway.internal'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASS', 'WimQnTTlRrXENFJqeJgfnQrsPRRkwexf'),
    'database': os.environ.get('DB_NAME', 'encryption_db'),
    'port': int(os.environ.get('DB_PORT', 3306))
}
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'admin_secret_please_change')

# --- Upload / file config ---
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

ALLOWED_OPERATIONS = {'encrypt', 'decrypt'}

# (optional) sqlite for uploads bookkeeping
sqlite_conn = sqlite3.connect(str(Path(__file__).resolve().parent / "file_data.db"), check_same_thread=False)
c = sqlite_conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    operation TEXT
)''')
sqlite_conn.commit()

logger = logging.getLogger(__name__)

def safe_filename(filename):
    return secure_filename(filename) or "file"

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# --- Admin blueprint ---
admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')

def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.headers.get('X-Admin-Token', '')
        if token != ADMIN_TOKEN:
            return jsonify({'error': 'forbidden'}), 403
        return f(*args, **kwargs)
    return wrapped

@admin_bp.route('/users', methods=['GET'])
@require_admin
def list_users():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                id,
                username,
                COALESCE(role, 'user') AS role,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
                DATE_FORMAT(last_login, '%Y-%m-%d %H:%i:%s') AS last_login
            FROM users
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall() or []
        return jsonify(rows), 200
    except Exception as e:
        logger.exception("admin list_users error")
        return jsonify({'error': 'db_error', 'detail': str(e)}), 500
    finally:
        try:
            if cur: cur.close()
            if conn: conn.close()
        except Exception:
            pass

# --- Safe blueprint registration helper ---
def register_blueprint_safely(app, bp):
    name = bp.name
    if name in app.blueprints:
        app.logger.debug("Blueprint '%s' already registered — skipping.", name)
        return
    try:
        app.register_blueprint(bp)
        app.logger.debug("Blueprint '%s' registered successfully.", name)
    except AssertionError as ex:
        app.logger.warning("Could not register blueprint '%s': %s", name, str(ex))

register_blueprint_safely(app, admin_bp)

# --- Registration ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Username and password required'}), 400
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({'status': 'fail', 'message': 'Username already exists'}), 409
        cursor.execute(
            "INSERT INTO users (username, password, created_at) VALUES (%s, %s, CURRENT_TIMESTAMP)",
            (username, hashed_password)
        )
        conn.commit()
        return jsonify({'status': 'success', 'message': 'User registered successfully'}), 201
    except Exception as e:
        app.logger.exception("Registration error")
        return jsonify({'status': 'fail', 'message': str(e)}), 500
    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
        except Exception:
            pass

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Username and password required'}), 400
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, hashed_password))
        user = cursor.fetchone()
        if not user:
            return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401
        # Update last_login (best-effort)
        try:
            upd_cursor = conn.cursor()
            upd_cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user.get('id'),))
            conn.commit()
            upd_cursor.close()
        except Exception:
            app.logger.debug("Could not update last_login", exc_info=True)
        role = user.get('role') if isinstance(user, dict) and 'role' in user else None
        if not role:
            role = 'admin' if user.get('username') == 'admin' else 'user'
        payload = {
            'status': 'success',
            'message': 'Login successful',
            'username': user.get('username'),
            'role': role
        }
        if role == 'admin':
            payload['admin_token'] = ADMIN_TOKEN
        return jsonify(payload), 200
    except Exception as e:
        app.logger.exception("Login error")
        return jsonify({'status': 'fail', 'message': str(e)}), 500
    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
        except Exception:
            pass


# --- Symmetric / RSA / File / DH / Resources routes kept as before ---
@app.route('/symmetric/encrypt', methods=['POST'])
def sym_encrypt():
    data = request.json or {}
    ct, key = symmetric.encrypt(data.get('plaintext', ''), data.get('algo'))
    return jsonify({'ciphertext': ct, 'key': key})

@app.route('/symmetric/decrypt', methods=['POST'])
def sym_decrypt():
    data = request.json or {}
    pt = symmetric.decrypt(data.get('ciphertext', ''), data.get('key'), data.get('algo'))
    return jsonify({'plaintext': pt})

@app.route('/rsa_keys', methods=['GET'])
def get_rsa_keys():
    pub_key, priv_key = asymmetric.get_keys()
    return jsonify({"public_key": pub_key, "private_key": priv_key})

@app.route('/rsa_encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.get_json() or {}
    message = data.get('message')
    pub_key = data.get('public')
    if not message or not pub_key:
        return jsonify({"error": "Missing message or public key"}), 400
    try:
        cipher_text = asymmetric.rsa_encrypt(message, pub_key)
        return jsonify({"cipher_text": cipher_text})
    except Exception as e:
        app.logger.exception("RSA encrypt error")
        return jsonify({"error": str(e)}), 500

@app.route('/rsa_decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.get_json() or {}
    cipher_text = data.get('cipher')
    priv_key = data.get('private')
    if not cipher_text or not priv_key:
        return jsonify({"error": "Missing cipher text or private key"}), 400
    try:
        decrypted_text = asymmetric.rsa_decrypt(cipher_text, priv_key)
        return jsonify({"decrypted_text": decrypted_text})
    except Exception as e:
        app.logger.exception("RSA decrypt error")
        return jsonify({"error": str(e)}), 500

@app.route('/file/process', methods=['POST'])
def process_file():
    try:
        if 'operation' not in request.form:
            return jsonify(error="Missing operation"), 400
        op = request.form['operation']
        if op not in ALLOWED_OPERATIONS:
            return jsonify(error="Invalid operation"), 400

        if 'file' not in request.files:
            return jsonify(error="No file uploaded"), 400
        uploaded = request.files['file']
        original_name = safe_filename(uploaded.filename)
        data = uploaded.read()  # bytes
        out_name_prefix = request.form.get('out_name', '').strip()

        # record upload in sqlite (optional)
        try:
            c.execute("INSERT INTO files (filename, operation) VALUES (?, ?)", (original_name, op))
            sqlite_conn.commit()
        except Exception:
            app.logger.debug("Could not record upload to sqlite", exc_info=True)

        if op == 'encrypt':
            ciphertext, key = encrypt_content(data)
            out_filename = (out_name_prefix + "_enc") if out_name_prefix else (original_name + ".enc")
            out_filename = safe_filename(out_filename)
            out_path = UPLOAD_DIR / out_filename
            with open(out_path, 'wb') as f:
                f.write(ciphertext)
            return jsonify(filename=out_filename, key=key.decode()), 200

        elif op == 'decrypt':
            key = request.form.get('key', '').strip()
            if not key:
                return jsonify(error="Missing key for decryption"), 400
            try:
                plaintext = decrypt_content(data, key)
            except Exception as e:
                app.logger.debug("Decrypt failed: %s", str(e))
                return jsonify(error="Decryption failed: invalid key or corrupted file"), 400

            stem = Path(original_name).stem
            base = out_name_prefix if out_name_prefix else stem
            out_filename = f"{base}.txt"
            out_filename = safe_filename(out_filename)
            out_path = UPLOAD_DIR / out_filename
            with open(out_path, 'wb') as f:
                f.write(plaintext)
            return jsonify(filename=out_filename), 200

    except Exception as e:
        tb = traceback.format_exc()
        app.logger.exception("Unhandled processing error")
        return jsonify(error="Processing error", detail=str(e), traceback=tb), 500

@app.route('/file/download/<path:filename>', methods=['GET'])
def download_file(filename):
    filename = safe_filename(filename)
    file_path = UPLOAD_DIR / filename
    if not file_path.exists():
        abort(404)
    return send_from_directory(str(UPLOAD_DIR), filename, as_attachment=True)

@app.route('/dh_simulate', methods=['POST'])
def dh_simulate():
    data = request.get_json() or {}
    result = key_exchange.simulate_dh(data)
    return jsonify(result)

@app.route('/resources', methods=['GET'])
def get_resources_route():
    return jsonify(resources.get_resources())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
