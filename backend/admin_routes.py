from flask import Blueprint, request, jsonify
from functools import wraps
import os
import mysql.connector
import logging

admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)

DB_CONFIG = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASS'),
    'database': os.environ.get('DB_NAME'),
    'port': int(os.environ.get('DB_PORT', 3306))
}

ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'admin_secret_please_change')

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.headers.get('X-Admin-Token', '')
        if token != ADMIN_TOKEN:
            return jsonify({'error': 'forbidden'}), 403
        return f(*args, **kwargs)
    return wrapped

@admin_bp.route('/admin/users', methods=['GET'])
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
                DATE_FORMAT(last_login, '%%Y-%%m-%%d %%H:%%i:%%s') AS last_login,
                DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
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

@admin_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if row and row.get('role') == 'admin':
            return jsonify({'error': 'cannot_delete_admin'}), 403
        del_cur = conn.cursor()
        del_cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        del_cur.close()
        return jsonify({'message': 'deleted'}), 200
    except Exception as e:
        logger.exception("admin delete_user error")
        return jsonify({'error': 'db_error', 'detail': str(e)}), 500
    finally:
        try:
            if cur: cur.close()
            if conn: conn.close()
        except Exception:
            pass
