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

# Project modules
import symmetric
import asymmetric
import key_exchange
import resources
from file_encrypt import encrypt_content, decrypt_content

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# ================= DB CONFIG =================
DB_CONFIG = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASS'),
    'database': os.environ.get('DB_NAME'),
    'port': int(os.environ.get('DB_PORT', 3306))
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# ================= FRONTEND =================
@app.route('/')
def login_page():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/index.html')
def index_page():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

# ================= AUTH =================
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = hashlib.sha256(data.get('password').encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                   (username, password))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'status': 'success'})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = hashlib.sha256(data.get('password').encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",
                   (username, password))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        role = user.get('role', 'user')
        return jsonify({
            'status': 'success',
            'username': user['username'],
            'role': role
        })
    else:
        return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

# ================= FILE =================
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@app.route('/file/process', methods=['POST'])
def process_file():
    try:
        op = request.form['operation']
        uploaded = request.files['file']

        data = uploaded.read()

        if op == 'encrypt':
            ciphertext, key = encrypt_content(data)
            filename = uploaded.filename + ".enc"

            path = UPLOAD_DIR / filename
            with open(path, 'wb') as f:
                f.write(ciphertext)

            return jsonify({'filename': filename, 'key': key.decode()})

        elif op == 'decrypt':
            key = request.form['key']
            plaintext = decrypt_content(data, key)

            filename = "decrypted.txt"
            path = UPLOAD_DIR / filename

            with open(path, 'wb') as f:
                f.write(plaintext)

            return jsonify({'filename': filename})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/file/download/<path:filename>')
def download_file(filename):
    return send_from_directory(str(UPLOAD_DIR), filename, as_attachment=True)

# ================= CRYPTO =================
@app.route('/symmetric/encrypt', methods=['POST'])
def sym_encrypt():
    data = request.json
    ct, key = symmetric.encrypt(data.get('plaintext'), data.get('algo'))
    return jsonify({'ciphertext': ct, 'key': key})

@app.route('/symmetric/decrypt', methods=['POST'])
def sym_decrypt():
    data = request.json
    pt = symmetric.decrypt(data.get('ciphertext'), data.get('key'), data.get('algo'))
    return jsonify({'plaintext': pt})

@app.route('/rsa_keys')
def rsa_keys():
    pub, priv = asymmetric.get_keys()
    return jsonify({'public': pub, 'private': priv})

@app.route('/rsa_encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json
    return jsonify({'cipher': asymmetric.rsa_encrypt(data['message'], data['public'])})

@app.route('/rsa_decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json
    return jsonify({'text': asymmetric.rsa_decrypt(data['cipher'], data['private'])})

@app.route('/dh_simulate', methods=['POST'])
def dh():
    return jsonify(key_exchange.simulate_dh(request.json))

@app.route('/resources')
def get_res():
    return jsonify(resources.get_resources())

# ================= RUN =================
if __name__ == '__main__':
    app.run(debug=True)
