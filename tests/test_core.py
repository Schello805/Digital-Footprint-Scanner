import asyncio
from app.modules.username_checker import PLATFORMS, _calculate_match_score
from app.modules.exif_inspector import extract_exif_metadata, strip_exif_metadata
from app.modules.domain_recon import check_domain_dns
from app.modules.breach_checker import check_password_pwned
from app.modules.dork_builder import generate_dorks
from app.modules.phone_recon import analyze_phone_number
from app.modules.identity_auditor import audit_identity_profile
from app.modules.full_scanner import execute_full_scan
from PIL import Image
import io
from app.modules.email_account_checker import check_email_accounts

def test_sync_modules():
    print(f"✓ Username checker loaded {len(PLATFORMS)} platforms.")

    # Test Context Match Scorer
    page_text = "Welcome to Michael Schmidt's personal page in Berlin. Passionate about Python."
    match = _calculate_match_score(page_text, full_name="Michael Schmidt", city="Berlin", keywords=["Python"])
    assert match["confidence"] == "high"
    assert match["score"] >= 70
    print(f"✓ Context Match Scorer verified! Confidence: {match['confidence']}, Score: {match['score']}%")

    # Test Phone Recon
    phone_res = analyze_phone_number("+49 171 1234567")
    assert phone_res["is_mobile"] is True
    print(f"✓ Phone Recon recognized mobile carrier: {phone_res['region_or_carrier']}")

    # Test Factual Identity Auditor without breaches (0% exposure, no assumptions)
    audit_clean = audit_identity_profile({
        "full_name": "Michael Schmidt",
        "cities": ["Berlin"],
        "employers": ["Siemens"],
        "phones": ["0171 9999999"]
    })
    assert audit_clean["success"] is True
    assert audit_clean["data"]["exposure_score"] == 0
    assert len(audit_clean["data"]["threat_vectors"]) == 0
    print("✓ Factual Identity Auditor verified: 0% exposure when no breaches detected (zero assumptions).")

    # Test Factual Identity Auditor with verified breach evidence
    audit_with_breach = audit_identity_profile(
        {"full_name": "Michael Schmidt"},
        scan_results={
            "password_result": {"pwned": True, "count": 14200},
            "email_result": {"breached": True, "breach_count": 2, "breach_names": ["LinkedIn", "Adobe"]}
        }
    )
    assert audit_with_breach["data"]["exposure_score"] >= 55
    assert len(audit_with_breach["data"]["threat_vectors"]) == 2
    print(f"✓ Evidence-based exposure audit verified: Score {audit_with_breach['data']['exposure_score']}% based strictly on verified breaches.")

async def test_full_scan_pipeline():
    # Test Full 1-Click Scan Pipeline
    print("Testing Full 1-Click Scan Orchestration...")
    scan_input = {
        "name": "Michael Schmidt",
        "username": "mikeshadow",
        "email": "michael.schmidt@test.com",
        "city": "Berlin",
        "employer": "Siemens",
        "phone": "0171 1234567",
        "domain": "schellenberger.biz"
    }
    res = await execute_full_scan(scan_input)
    assert res["success"] is True
    assert "summary" in res
    assert "identity_audit" in res
    assert "found_profiles" in res
    assert "dorks" in res
    assert "web_directories" in res
    assert len(res["web_directories"]) >= 6
    # Verify own website presence included
    dom_presence = next((p for p in res["found_profiles"] if "schellenberger.biz" in p.get("url", "")), None)
    assert dom_presence is not None
    assert dom_presence["exists"] is True
    print(f"✓ Full 1-Click Scan passed! Web Directories: {len(res['web_directories'])}, Profiles: {len(res['found_profiles'])}, Exposure Score: {res['summary']['exposure_score']}")

    # Test Email Account Checker
    print("Testing Email Account Recon...")
    invalid_res = await check_email_accounts("invalid-email")
    assert invalid_res["success"] is False
    print("✓ Email Account Recon handles invalid input gracefully.")

    # Test Discovered Images Word Cloud Aggregator
    print("Testing Visual Media Cloud & Image Sizing...")
    from app.modules.image_recon import collect_discovered_images
    mock_email_recon = {
        "avatar_url": "https://2.gravatar.com/avatar/abc12345?s=400",
        "registered_accounts": [
            {
                "service": "Duolingo",
                "avatar_url": "https://0.gravatar.com/avatar/abc12345?s=200",
                "profile_url": "https://duolingo.com/profile/testuser"
            }
        ]
    }
    mock_profiles = [
        {"platform": "GitHub", "url": "https://github.com/testuser", "exists": True}
    ]
    imgs = collect_discovered_images(
        email_recon_res=mock_email_recon,
        found_profiles=mock_profiles,
        session_avatar="https://lh3.googleusercontent.com/a/userphoto"
    )
    assert len(imgs) == 3
    # Gravatar image was found on 2 platforms -> scaled to medium/large
    grav_img = next(i for i in imgs if "gravatar" in i["id"])
    assert grav_img["count"] == 2
    assert grav_img["size_tier"] == "lg"
    assert len(grav_img["sources"]) == 2
    assert "google_lens_url" in grav_img
    print(f"✓ Visual Media Cloud verified! {len(imgs)} distinct images correctly grouped, weighted and tiered.")

if __name__ == "__main__":
    test_sync_modules()
    asyncio.run(test_full_scan_pipeline())
    print("🎉 All Full Scan tests passed successfully!")
