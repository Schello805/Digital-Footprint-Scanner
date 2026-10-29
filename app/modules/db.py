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

            conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                email TEXT PRIMARY KEY,
                failed_count INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0,
                last_attempt INTEGER DEFAULT 0
            );
            """)

            # Schema Migrations
            for col_def in [
                ("name", "TEXT"),
                ("avatar_url", "TEXT"),
                ("oauth_data", "TEXT")
            ]:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col_def[0]} {col_def[1]};")
                except Exception:
                    pass

            # Migration: Encrypt any existing plaintext scans
            try:
                from app.modules.crypto import encrypt_payload
                plain_rows = conn.execute(
                    "SELECT id, raw_payload_json, raw_results_json FROM scans WHERE raw_payload_json NOT LIKE 'enc:v1:%'"
                ).fetchall()
                for r in plain_rows:
                    enc_payload = encrypt_payload(r["raw_payload_json"])
                    enc_results = encrypt_payload(r["raw_results_json"])
                    conn.execute(
                        "UPDATE scans SET raw_payload_json = ?, raw_results_json = ? WHERE id = ?",
                        (enc_payload, enc_results, r["id"])
                    )
            except Exception:
                pass
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

def get_or_create_oauth_user(
    email: str, 
    provider: str, 
    oauth_id: str = "",
    name: str = "",
    avatar_url: str = "",
    oauth_data: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Finds or creates a user account authenticated via Google or GitHub OAuth,
    storing verified profile data for automated scanner prefilling.
    Returns: (user_dict, session_token, error_message)
    """
    email_clean = email.strip().lower()
    if not email_clean or "@" not in email_clean:
        return None, None, "Ungültige E-Mail-Adresse vom OAuth-Provider."

    oauth_json = json.dumps(oauth_data or {}, ensure_ascii=False)
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, email, name, avatar_url FROM users WHERE email = ?", (email_clean,)).fetchone()
        if user:
            user_id = user["id"]
            with conn:
                conn.execute("""
                    UPDATE users 
                    SET name = CASE WHEN ? != '' THEN ? ELSE name END,
                        avatar_url = CASE WHEN ? != '' THEN ? ELSE avatar_url END,
                        oauth_data = ?
                    WHERE id = ?
                """, (name, name, avatar_url, avatar_url, oauth_json, user_id))
        else:
            salt_hex = os.urandom(16).hex()
            pwd_hash = f"OAUTH_{provider.upper()}_{secrets.token_hex(16)}"
            with conn:
                cursor = conn.execute(
                    "INSERT INTO users (email, password_hash, salt, name, avatar_url, oauth_data) VALUES (?, ?, ?, ?, ?, ?)",
                    (email_clean, pwd_hash, salt_hex, name, avatar_url, oauth_json)
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

        return {"id": user_id, "email": email_clean, "name": name, "avatar_url": avatar_url}, token, None
    except Exception as e:
        return None, None, f"OAuth-Fehler: {str(e)}"
    finally:
        conn.close()

# Static dummy salt for timing attack resistance
_DUMMY_SALT = b"dummy_salt_timing_safe_16b"

def _record_failed_attempt(conn: sqlite3.Connection, email: str, now: int):
    """Records failed login attempt and triggers temporary 15-minute account lock after 5 failures."""
    try:
        row = conn.execute("SELECT failed_count, locked_until FROM login_attempts WHERE email = ?", (email,)).fetchone()
        if not row:
            with conn:
                conn.execute(
                    "INSERT INTO login_attempts (email, failed_count, locked_until, last_attempt) VALUES (?, 1, 0, ?)",
                    (email, now)
                )
        else:
            new_count = 1 if (row["locked_until"] > 0 and row["locked_until"] <= now) else row["failed_count"] + 1
            locked_until = now + (15 * 60) if new_count >= 5 else 0
            with conn:
                conn.execute(
                    "UPDATE login_attempts SET failed_count = ?, locked_until = ?, last_attempt = ? WHERE email = ?",
                    (new_count, locked_until, now, email)
                )
    except Exception:
        pass

def _get_remaining_attempts(conn: sqlite3.Connection, email: str) -> int:
    try:
        row = conn.execute("SELECT failed_count, locked_until FROM login_attempts WHERE email = ?", (email,)).fetchone()
        if not row:
            return 5
        if row["locked_until"] > int(time.time()):
            return 0
        return max(0, 5 - row["failed_count"])
    except Exception:
        return 5

def login_user(email: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Authenticates user with timing side-channel attack protection and 5-attempt brute-force lockout.
    Returns: (user_dict, session_token, error_message)
    """
    email_clean = email.strip().lower()
    now = int(time.time())
    conn = get_db_connection()
    try:
        # Check brute force lockout
        attempt = conn.execute("SELECT * FROM login_attempts WHERE email = ?", (email_clean,)).fetchone()
        if attempt and attempt["locked_until"] > now:
            mins_left = int((attempt["locked_until"] - now) / 60) + 1
            _hash_password(password, _DUMMY_SALT) # preserve timing
            return None, None, f"Konto temporär geschützt. Bitte warte noch {mins_left} Minute(n) vor dem nächsten Versuch."

        user = conn.execute("SELECT * FROM users WHERE email = ?", (email_clean,)).fetchone()
        if not user:
            # Perform dummy scrypt computation to match execution time and prevent user enumeration
            _hash_password(password, _DUMMY_SALT)
            _record_failed_attempt(conn, email_clean, now)
            left = _get_remaining_attempts(conn, email_clean)
            if left <= 0:
                return None, None, "Zu viele Fehlversuche. Dieses Konto wurde für 15 Minuten gesperrt."
            return None, None, f"E-Mail oder Passwort ungültig. (Noch {left} Versuche bis zur Kontosperre)"

        salt_bytes = bytes.fromhex(user["salt"])
        expected_hash = _hash_password(password, salt_bytes)
        if not secrets.compare_digest(user["password_hash"], expected_hash):
            _record_failed_attempt(conn, email_clean, now)
            left = _get_remaining_attempts(conn, email_clean)
            if left <= 0:
                return None, None, "Zu viele Fehlversuche. Dieses Konto wurde für 15 Minuten gesperrt."
            return None, None, f"E-Mail oder Passwort ungültig. (Noch {left} Versuche bis zur Kontosperre)"

        # Successful login: reset failed attempts
        with conn:
            conn.execute("DELETE FROM login_attempts WHERE email = ?", (email_clean,))

        # Create session
        token = secrets.token_urlsafe(32)
        expires_at = now + (30 * 86400) # 30 days
        with conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user["id"], expires_at)
            )

        return {"id": user["id"], "email": user["email"]}, token, None
    finally:
        conn.close()

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Resolves a session token to the corresponding user account with prefill profile data."""
    if not token:
        return None
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT u.*, s.expires_at 
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

        keys = row.keys()
        email = row["email"]
        name = row["name"] if ("name" in keys and row["name"]) else ""
        avatar_url = row["avatar_url"] if ("avatar_url" in keys and row["avatar_url"]) else ""
        raw_oauth = row["oauth_data"] if ("oauth_data" in keys and row["oauth_data"]) else ""
        oauth_dict = json.loads(raw_oauth) if raw_oauth else {}

        # Infer prefill details from Google / GitHub data
        domain = ""
        if "@" in email:
            domain = email.split("@")[1].strip()
        username = oauth_dict.get("login") or (email.split("@")[0].strip() if "@" in email else "")
        city = oauth_dict.get("location") or ""
        employer = oauth_dict.get("company") or ""

        return {
            "id": row["id"],
            "email": email,
            "name": name,
            "avatar_url": avatar_url,
            "prefill": {
                "name": name,
                "email": email,
                "username": username,
                "domain": domain,
                "city": city,
                "employer": employer,
            }
        }
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
    """Saves a completed full scan into the user's private audit archive with AES at-rest encryption."""
    target_name = payload.get("name") or results.get("resolved_name") or ""
    target_handle = payload.get("username") or results.get("resolved_username") or results.get("discovered_handle") or ""
    target_email = payload.get("email") or ""

    summary = results.get("summary") or {}
    exposure_score = summary.get("exposure_score", 0)
    exposure_level = summary.get("exposure_level", "GERING")
    profiles_found = summary.get("profiles_found", len(results.get("found_profiles", [])))
    high_matches = summary.get("high_confidence_matches", 0)

    from app.modules.crypto import encrypt_payload
    payload_json = encrypt_payload(json.dumps(payload, ensure_ascii=False))
    results_json = encrypt_payload(json.dumps(results, ensure_ascii=False))

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

        from app.modules.crypto import decrypt_payload
        data = dict(row)
        raw_payload = decrypt_payload(data["raw_payload_json"]) if data["raw_payload_json"] else "{}"
        raw_results = decrypt_payload(data["raw_results_json"]) if data["raw_results_json"] else "{}"
        data["payload"] = json.loads(raw_payload) if raw_payload else {}
        data["results"] = json.loads(raw_results) if raw_results else {}
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
