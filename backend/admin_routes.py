from flask import Blueprint, request, jsonify
from functools import wraps
import os
import logging
from db import get_connection

admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)

ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'admin_secret_please_change')

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
        conn = get_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                id,
                username,
                COALESCE(role, 'user') AS role,
                TO_CHAR(last_login, 'YYYY-MM-DD HH24:MI:SS'),
                TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS'),
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
