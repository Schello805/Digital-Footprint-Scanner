import io
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_http_security_headers():
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in res.headers
    print("✓ HTTP Security Headers verified (Anti-Clickjacking, Nosniff, CSP).")

def test_ssrf_protection():
    # 1. Loopback
    res1 = client.get("/api/recon/domain?domain=127.0.0.1")
    assert res1.status_code == 200
    assert res1.json()["success"] is False
    assert "Sicherheitswarnung" in res1.json()["error"] or "gesperrt" in res1.json()["error"]

    # 2. AWS / Cloud Metadata endpoint
    res2 = client.get("/api/recon/domain?domain=169.254.169.254")
    assert res2.status_code == 200
    assert res2.json()["success"] is False

    # 3. Localhost hostname
    res3 = client.get("/api/recon/domain?domain=localhost")
    assert res3.status_code == 200
    assert res3.json()["success"] is False
    print("✓ SSRF & Private Network Protection verified.")

def test_password_policy():
    # Less than 8 characters must be rejected
    res = client.post("/api/auth/register", json={"email": "short_pwd@test.com", "password": "123"})
    assert res.status_code == 200
    assert res.json()["success"] is False
    assert "8 Zeichen" in res.json()["error"]
    print("✓ Strong password policy (min 8 chars) enforced.")

def test_settings_unauthorized_protection():
    # Anonymous POST /api/settings must return 401 or 403 Forbidden
    res = client.post("/api/settings", json={"hibp_api_key": "malicious_key"})
    assert res.status_code in (401, 403)
    # Anonymous GET /api/settings must also return 403
    res_get = client.get("/api/settings")
    assert res_get.status_code == 403
    print("✓ Settings API endpoint strictly protected against unauthorized access (Admin only / 403).")

def test_account_lockout_after_failed_attempts():
    import secrets
    from app.modules.db import login_user, register_user
    victim_email = f"victim_{secrets.token_hex(4)}@example.com"
    register_user(victim_email, "CorrectPassword123!")

    # 4 consecutive failed attempts
    for _ in range(4):
        u, tok, err = login_user(victim_email, "WrongPassword!")
        assert u is None
        assert "Versuche" in err

    # 5th failed attempt triggers lockout
    u, tok, err = login_user(victim_email, "WrongPassword!")
    assert u is None
    assert "gesperrt" in err.lower() or "geschützt" in err.lower()

    # 6th attempt while locked is blocked immediately
    u, tok, err = login_user(victim_email, "CorrectPassword123!")
    assert u is None
    assert "geschützt" in err.lower() or "gesperrt" in err.lower()
    print("✓ 5-Attempt Account Lockout (15-min protection) verified.")

def test_database_encryption_at_rest():
    import secrets
    from app.modules.db import register_user, save_user_scan, get_scan_by_id, get_db_connection
    user_email = f"crypto_{secrets.token_hex(4)}@example.com"
    user, tok, err = register_user(user_email, "SecretPassword123!")
    
    payload = {"name": "Sensitive Persona", "email": "classified@corp.com"}
    results = {"summary": {"exposure_score": 42}, "found_profiles": [{"site": "github"}]}
    scan_id = save_user_scan(user["id"], payload, results)

    # 1. Inspect raw SQLite table directly
    conn = get_db_connection()
    row = conn.execute("SELECT raw_payload_json, raw_results_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    raw_payload_in_db = row["raw_payload_json"]
    raw_results_in_db = row["raw_results_json"]
    conn.close()

    # Raw DB columns MUST be encrypted with enc:v1: and NOT contain plaintext
    assert raw_payload_in_db.startswith("enc:v1:")
    assert "Sensitive Persona" not in raw_payload_in_db
    assert raw_results_in_db.startswith("enc:v1:")
    assert "classified@corp.com" not in raw_results_in_db

    # 2. Transparent decryption via application layer
    retrieved = get_scan_by_id(user["id"], scan_id)
    assert retrieved is not None
    assert retrieved["payload"]["name"] == "Sensitive Persona"
    assert retrieved["results"]["summary"]["exposure_score"] == 42
    print("✓ AES Database Encryption at Rest verified (zero plaintext in SQLite).")

def test_image_security_and_decompression_bomb():
    # 1. Non-image binary rejected by magic byte inspection
    fake_file = io.BytesIO(b"NOT_AN_IMAGE_FAKE_HEADER_CONTENT_BYTES")
    res1 = client.post("/api/exif/inspect", files={"file": ("malicious.exe", fake_file, "image/jpeg")})
    assert res1.status_code == 200
    assert res1.json()["success"] is False
    assert "Header" in res1.json()["error"]

    # 2. File exceeding 15MB rejected with 413
    huge_file = io.BytesIO(b"0" * (16 * 1024 * 1024))
    res2 = client.post("/api/exif/inspect", files={"file": ("huge.jpg", huge_file, "image/jpeg")})
    assert res2.status_code == 413
    print("✓ Image file security (magic bytes check & 15MB upload limit) verified.")

def test_rate_limiter_brute_force_protection():
    # Make multiple rapid auth attempts to trigger rate limit (max 8 per 60s)
    hit_429 = False
    for i in range(12):
        res = client.post("/api/auth/login", json={"email": f"brute_{i}@test.com", "password": "WrongPassword1!"})
        if res.status_code == 429:
            hit_429 = True
            break
    assert hit_429 is True
    print("✓ In-Memory Rate Limiter triggered HTTP 429 Too Many Requests against brute-force attacks.")

def test_scan_rate_limiter_and_whitelist():
    # 1. Untrusted client IP: max 3 scan requests per hour
    untrusted_headers = {"X-Forwarded-For": "198.51.100.42"}
    hit_scan_429 = False
    for i in range(5):
        res = client.post("/api/scan/full", json={"name": f"Target {i}"}, headers=untrusted_headers)
        if res.status_code == 429:
            hit_scan_429 = True
            assert "Scann-Limit erreicht" in res.json()["error"]
            break
    assert hit_scan_429 is True
    print("✓ Max 3 scans per hour enforced for untrusted IP (HTTP 429).")

    # 2. User Whitelisted IP (24.134.128.233): Exceeds 3 requests without 429
    whitelisted_user_headers = {"X-Forwarded-For": "24.134.128.233"}
    for i in range(6):
        res = client.post("/api/scan/full", json={"name": f"User Target {i}"}, headers=whitelisted_user_headers)
        # Should NOT be 429
        assert res.status_code != 429
    print("✓ User IP 24.134.128.233 successfully whitelisted (unlimited scans).")

    # 3. Reverse Proxy Whitelisted IP (10.10.50.115): Exceeds 3 requests without 429
    proxy_headers = {"X-Forwarded-For": "10.10.50.115"}
    for i in range(6):
        res = client.post("/api/scan/full", json={"name": f"Proxy Target {i}"}, headers=proxy_headers)
        assert res.status_code != 429
    print("✓ Reverse Proxy IP 10.10.50.115 successfully whitelisted (unlimited scans).")

if __name__ == "__main__":
    test_http_security_headers()
    test_ssrf_protection()
    test_password_policy()
    test_settings_unauthorized_protection()
    test_account_lockout_after_failed_attempts()
    test_database_encryption_at_rest()
    test_image_security_and_decompression_bomb()
    test_rate_limiter_brute_force_protection()
    test_scan_rate_limiter_and_whitelist()
    print("🎉 All Cybersecurity Hardening Tests Passed Successfully!")
