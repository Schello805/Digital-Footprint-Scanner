import os
import time
import secrets
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_auth_and_user_scans_workflow():
    test_email = f"tester_{int(time.time())}_{secrets.token_hex(4)}@example.com"
    test_password = "SecurePassword123!"

    # 1. Register
    reg_resp = client.post("/api/auth/register", json={"email": test_email, "password": test_password})
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    assert reg_data["user"]["email"] == test_email
    token = reg_data["token"]
    print("✓ User registration verified successfully.")

    # 2. Duplicate registration blocked
    dup_resp = client.post("/api/auth/register", json={"email": test_email, "password": test_password})
    assert dup_resp.status_code == 200
    assert dup_resp.json()["success"] is False
    print("✓ Duplicate email registration rejected gracefully.")

    # 3. Check /api/auth/me (authenticated via cookie set in register)
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["authenticated"] is True
    assert me_data["user"]["email"] == test_email
    print("✓ Session authentication verified via /api/auth/me.")

    # 4. List user scans (starts empty)
    scans_resp = client.get("/api/user/scans")
    assert scans_resp.status_code == 200
    assert len(scans_resp.json()["scans"]) == 0
    print("✓ User private scan archive initialized empty.")

    # 5. Run a full scan (with authenticated session)
    scan_payload = {
        "name": "Audit Target",
        "username": "audittarget123",
        "email": "target@example.com"
    }
    scan_resp = client.post("/api/scan/full", json=scan_payload)
    assert scan_resp.status_code == 200
    scan_res_data = scan_resp.json()
    assert scan_res_data["success"] is True
    assert "saved_scan_id" in scan_res_data
    saved_id = scan_res_data["saved_scan_id"]
    print(f"✓ Authenticated full scan automatically archived with ID {saved_id}.")

    # 6. Verify scan appears in user's history
    scans_resp2 = client.get("/api/user/scans")
    assert scans_resp2.status_code == 200
    user_scans = scans_resp2.json()["scans"]
    assert len(user_scans) == 1
    assert user_scans[0]["id"] == saved_id
    assert user_scans[0]["target_name"] == "Audit Target"
    print(f"✓ Scan history listed {len(user_scans)} archived dossier.")

    # 7. Get full scan detail
    detail_resp = client.get(f"/api/user/scans/{saved_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()["scan"]
    assert detail_data["id"] == saved_id
    assert "results" in detail_data
    assert "payload" in detail_data
    print("✓ Complete dossier retrieval verified.")

    # 8. Delete scan
    del_resp = client.delete(f"/api/user/scans/{saved_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    scans_resp3 = client.get("/api/user/scans")
    assert len(scans_resp3.json()["scans"]) == 0
    print("✓ Dossier deletion from archive verified.")

    # 9. Logout
    logout_resp = client.post("/api/auth/logout")
    assert logout_resp.status_code == 200
    me_resp2 = client.get("/api/auth/me")
    assert me_resp2.json()["authenticated"] is False
    print("✓ User logout verified successfully.")

    # 10. Unauthorized access rejected after logout
    unauth_resp = client.get("/api/user/scans")
    assert unauth_resp.status_code == 401
    print("✓ Unauthorized archive access rejected (401).")

if __name__ == "__main__":
    test_auth_and_user_scans_workflow()
    print("🎉 All Auth & User Scan Archive tests passed!")
