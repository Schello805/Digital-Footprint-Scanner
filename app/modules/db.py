import os
import sqlite3
import json
import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional, Tuple

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "footprint.db")

def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_name TEXT,
                target_handle TEXT,
                target_email TEXT,
                exposure_score INTEGER DEFAULT 0,
                exposure_level TEXT DEFAULT 'GERING',
                profiles_found INTEGER DEFAULT 0,
                high_confidence_matches INTEGER DEFAULT 0,
                raw_payload_json TEXT,
                raw_results_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS unsub_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_service TEXT NOT NULL,
                email_used TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """)
    finally:
        conn.close()

# Initialize DB on module import
init_db()

# ==================== PASSWORD & HASHING ====================

def _hash_password(password: str, salt_bytes: bytes) -> str:
    """Uses scrypt KDF for secure, memory-hard password hashing."""
    return hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1).hex()

# ==================== USER AUTHENTICATION ====================

def register_user(email: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Registers a new user account with strong password requirements.
    Returns: (user_dict, session_token, error_message)
    """
    email_clean = email.strip().lower()
    if not email_clean or "@" not in email_clean:
        return None, None, "Bitte eine gültige E-Mail-Adresse eingeben."
    if len(password) < 8:
        return None, None, "Das Passwort muss mindestens 8 Zeichen lang sein (NIST Cybersecurity Standard)."

    salt_bytes = os.urandom(16)
    salt_hex = salt_bytes.hex()
    pwd_hash = _hash_password(password, salt_bytes)

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(
                "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
                (email_clean, pwd_hash, salt_hex)
            )
            user_id = cursor.lastrowid
            
            # Create Session
            token = secrets.token_urlsafe(32)
            expires_at = int(time.time()) + (30 * 86400) # 30 days
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user_id, expires_at)
            )

            return {"id": user_id, "email": email_clean}, token, None
    except sqlite3.IntegrityError:
        return None, None, "Diese E-Mail-Adresse ist bereits registriert. Bitte anmelden."
    except Exception as e:
        return None, None, f"Fehler bei der Registrierung: {str(e)}"
    finally:
        conn.close()

def get_or_create_oauth_user(email: str, provider: str, oauth_id: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Finds or creates a user account authenticated via Google or GitHub OAuth.
    Returns: (user_dict, session_token, error_message)
    """
    email_clean = email.strip().lower()
    if not email_clean or "@" not in email_clean:
        return None, None, "Ungültige E-Mail-Adresse vom OAuth-Provider."

    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email FROM users WHERE email = ?", (email_clean,)).fetchone()
        if user:
            user_id = user["id"]
        else:
            salt_hex = os.urandom(16).hex()
            pwd_hash = f"OAUTH_{provider.upper()}_{secrets.token_hex(16)}"
            with conn:
                cursor = conn.execute(
                    "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
                    (email_clean, pwd_hash, salt_hex)
                )
                user_id = cursor.lastrowid

        # Create session
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + (30 * 86400) # 30 days
        with conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user_id, expires_at)
            )

        return {"id": user_id, "email": email_clean}, token, None
    except Exception as e:
        return None, None, f"OAuth-Fehler: {str(e)}"
    finally:
        conn.close()

# Static dummy salt for timing attack resistance
_DUMMY_SALT = b"dummy_salt_timing_safe_16b"

def login_user(email: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Authenticates an existing user with timing side-channel attack protection.
    Returns: (user_dict, session_token, error_message)
    """
    email_clean = email.strip().lower()
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email_clean,)).fetchone()
        if not user:
            # Perform dummy scrypt computation to match execution time and prevent user enumeration
            _hash_password(password, _DUMMY_SALT)
            return None, None, "E-Mail oder Passwort ungültig."

        salt_bytes = bytes.fromhex(user["salt"])
        expected_hash = _hash_password(password, salt_bytes)
        if not secrets.compare_digest(user["password_hash"], expected_hash):
            return None, None, "E-Mail oder Passwort ungültig."

        # Create session
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + (30 * 86400) # 30 days
        with conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user["id"], expires_at)
            )

        return {"id": user["id"], "email": user["email"]}, token, None
    finally:
        conn.close()

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Resolves a session token to the corresponding user account."""
    if not token:
        return None
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT u.id, u.email, s.expires_at 
            FROM sessions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.token = ?
        """, (token,)).fetchone()

        if not row:
            return None
        
        # Check expiration
        if row["expires_at"] < int(time.time()):
            with conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return None

        return {"id": row["id"], "email": row["email"]}
    finally:
        conn.close()

def logout_token(token: str):
    """Deletes a session token upon logout."""
    if not token:
        return
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    finally:
        conn.close()

# ==================== SCANS MANAGEMENT ====================

def save_user_scan(user_id: int, payload: Dict[str, Any], results: Dict[str, Any]) -> int:
    """Saves a completed full scan into the user's private audit archive."""
    target_name = payload.get("name") or results.get("resolved_name") or ""
    target_handle = payload.get("username") or results.get("resolved_username") or results.get("discovered_handle") or ""
    target_email = payload.get("email") or ""

    summary = results.get("summary") or {}
    exposure_score = summary.get("exposure_score", 0)
    exposure_level = summary.get("exposure_level", "GERING")
    profiles_found = summary.get("profiles_found", len(results.get("found_profiles", [])))
    high_matches = summary.get("high_confidence_matches", 0)

    payload_json = json.dumps(payload, ensure_ascii=False)
    results_json = json.dumps(results, ensure_ascii=False)

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scans (
                    user_id, target_name, target_handle, target_email,
                    exposure_score, exposure_level, profiles_found, high_confidence_matches,
                    raw_payload_json, raw_results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, target_name, target_handle, target_email,
                exposure_score, exposure_level, profiles_found, high_matches,
                payload_json, results_json
            ))
            return cursor.lastrowid
    finally:
        conn.close()

def get_user_scans_list(user_id: int) -> List[Dict[str, Any]]:
    """Returns a list of all historical scans for a user (without heavy payload blobs)."""
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT id, target_name, target_handle, target_email,
                   exposure_score, exposure_level, profiles_found, high_confidence_matches,
                   created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()
        
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_scan_by_id(user_id: int, scan_id: int) -> Optional[Dict[str, Any]]:
    """Returns the full scan data (including raw results) for re-rendering."""
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT * FROM scans WHERE id = ? AND user_id = ?
        """, (scan_id, user_id)).fetchone()

        if not row:
            return None

        data = dict(row)
        data["payload"] = json.loads(data["raw_payload_json"]) if data["raw_payload_json"] else {}
        data["results"] = json.loads(data["raw_results_json"]) if data["raw_results_json"] else {}
        del data["raw_payload_json"]
        del data["raw_results_json"]
        return data
    finally:
        conn.close()

def delete_user_scan(user_id: int, scan_id: int) -> bool:
    """Deletes a scan from user history."""
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
            return cursor.rowcount > 0
    finally:
        conn.close()
