import asyncio
from app.modules.username_checker import PLATFORMS, _calculate_match_score
from app.modules.exif_inspector import extract_exif_metadata, strip_exif_metadata
from app.modules.domain_recon import check_domain_dns
from app.modules.breach_checker import check_password_pwned
from app.modules.dork_builder import generate_dorks
from app.modules.email_permutator import generate_email_permutations
from app.modules.phone_recon import analyze_phone_number
from app.modules.identity_auditor import audit_identity_profile
from app.modules.full_scanner import execute_full_scan
from PIL import Image
import io

def test_sync_modules():
    print(f"✓ Username checker loaded {len(PLATFORMS)} platforms.")

    # Test False Positive / Match Scorer
    page_text = "Welcome to Michael Schmidt's personal page in Berlin. Passionate about Python."
    match = _calculate_match_score(page_text, full_name="Michael Schmidt", city="Berlin", keywords=["Python"])
    assert match["confidence"] == "high"
    assert match["score"] >= 70
    print(f"✓ Context Match Scorer verified! Confidence: {match['confidence']}, Score: {match['score']}%")

    # Test Email Permutator
    perms = generate_email_permutations("Michael", "Schmidt", "siemens.com")
    assert "michael.schmidt@siemens.com" in perms
    print(f"✓ Email Permutator generated {len(perms)} realistic email addresses.")

    # Test Phone Recon
    phone_res = analyze_phone_number("+49 171 1234567")
    assert phone_res["is_mobile"] is True
    print(f"✓ Phone Recon recognized mobile carrier: {phone_res['region_or_carrier']}")

    # Test Identity Auditor
    audit_res = audit_identity_profile({
        "full_name": "Michael Schmidt",
        "cities": ["Berlin"],
        "employers": ["Siemens"],
        "phones": ["0171 9999999"]
    })
    assert audit_res["success"] is True
    print(f"✓ Identity Auditor generated Exposure Score: {audit_res['data']['exposure_score']}")

async def test_full_scan_pipeline():
    # Test Full 1-Click Scan Pipeline
    print("Testing Full 1-Click Scan Orchestration...")
    scan_input = {
        "name": "Michael Schmidt",
        "username": "mikeshadow",
        "email": "michael.schmidt@test.com",
        "city": "Berlin",
        "employer": "Siemens",
        "phone": "0171 1234567"
    }
    res = await execute_full_scan(scan_input)
    assert res["success"] is True
    assert "summary" in res
    assert "identity_audit" in res
    assert "found_profiles" in res
    assert "dorks" in res
    print(f"✓ Full 1-Click Scan passed! Exposure Score: {res['summary']['exposure_score']}, Dorks: {len(res['dorks'])}")

if __name__ == "__main__":
    test_sync_modules()
    asyncio.run(test_full_scan_pipeline())
    print("🎉 All Full Scan tests passed successfully!")
