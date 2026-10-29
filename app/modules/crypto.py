import os
import base64
import hashlib
from cryptography.fernet import Fernet

KEY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
KEY_FILE = os.path.join(KEY_DIR, ".encryption_key")
ENC_PREFIX = "enc:v1:"

def _get_or_create_key() -> bytes:
    """Retrieves or creates a 256-bit encryption key for database at-rest protection."""
    env_key = os.getenv("DATABASE_ENCRYPTION_KEY")
    if env_key:
        digest = hashlib.sha256(env_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read().strip()
                if len(key) == 44:
                    return key
        except Exception:
            pass

    # Generate new key and save with restricted file permissions
    new_key = Fernet.generate_key()
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(KEY_FILE, flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
    except Exception:
        pass
    return new_key

_FERNET_INSTANCE = None

def _get_fernet() -> Fernet:
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        key = _get_or_create_key()
        _FERNET_INSTANCE = Fernet(key)
    return _FERNET_INSTANCE

def encrypt_payload(plain_text: str) -> str:
    """Encrypts plaintext string using AES-CBC/HMAC at-rest encryption."""
    if not plain_text:
        return ""
    if plain_text.startswith(ENC_PREFIX):
        return plain_text # Already encrypted
    fernet = _get_fernet()
    token = fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")
    return f"{ENC_PREFIX}{token}"

def decrypt_payload(cipher_text: str) -> str:
    """Decrypts ciphertext string, or returns plaintext as-is if unencrypted (backward compatibility)."""
    if not cipher_text:
        return ""
    if not cipher_text.startswith(ENC_PREFIX):
        return cipher_text # Plaintext fallback
    raw_token = cipher_text[len(ENC_PREFIX):]
    try:
        fernet = _get_fernet()
        return fernet.decrypt(raw_token.encode("utf-8")).decode("utf-8")
    except Exception:
        # If decryption fails (e.g. key changed), return safe empty json string
        return "{}"
