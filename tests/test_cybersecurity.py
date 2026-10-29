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
    # Anonymous POST /api/settings must return 401
    res = client.post("/api/settings", json={"hibp_api_key": "malicious_key"})
    assert res.status_code == 401
    print("✓ Settings API endpoint protected against unauthorized mutation.")

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

if __name__ == "__main__":
    test_http_security_headers()
    test_ssrf_protection()
    test_password_policy()
    test_settings_unauthorized_protection()
    test_image_security_and_decompression_bomb()
    test_rate_limiter_brute_force_protection()
    print("🎉 All Cybersecurity Hardening Tests Passed Successfully!")
