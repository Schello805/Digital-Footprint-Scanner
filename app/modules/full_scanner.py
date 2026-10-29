import asyncio
from typing import Dict, Any, Optional, List
from app.modules.username_checker import scan_usernames_fast
from app.modules.breach_checker import check_password_pwned, check_email_breach
from app.modules.domain_recon import check_domain_dns
from app.modules.phone_recon import analyze_phone_number
from app.modules.mailing_list_checker import check_mailing_lists
from app.modules.dork_builder import generate_dorks
from app.modules.identity_auditor import audit_identity_profile
from app.config import settings

async def execute_full_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a comprehensive, orchestrated 1-click audit across all OSINT footprint vectors concurrently.
    """
    name = data.get("name", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    domain = data.get("domain", "").strip()
    phone = data.get("phone", "").strip()
    city = data.get("city", "").strip()
    employer = data.get("employer", "").strip()
    raw_keywords = data.get("keywords", "")
    
    keywords = [k.strip() for k in raw_keywords.split(",") if k.strip()] if isinstance(raw_keywords, str) else (raw_keywords or [])

    # 1. Identity & Threat Vector Baseline
    id_data = {
        "full_name": name,
        "usernames": [username] if username else [],
        "cities": [city] if city else [],
        "employers": [employer] if employer else [],
        "emails": [email] if email else [],
        "phones": [phone] if phone else [],
        "keywords": keywords
    }
    identity_audit = audit_identity_profile(id_data)

    # 2. Prepare Async Tasks
    tasks = []

    # Username task
    async def do_username_scan():
        if not username:
            return []
        ctx = {"name": name, "city": city, "employer": employer, "keywords": keywords}
        return await scan_usernames_fast(username, context=ctx)
    tasks.append(do_username_scan())

    # Password task
    async def do_password_check():
        if not password:
            return None
        return await check_password_pwned(password)
    tasks.append(do_password_check())

    # Email task
    async def do_email_check():
        if not email:
            return None
        return await check_email_breach(email, api_key=settings.hibp_api_key)
    tasks.append(do_email_check())

    # Domain task (sync function, run in executor)
    async def do_domain_check():
        if not domain:
            return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, check_domain_dns, domain)
    tasks.append(do_domain_check())

    # Mailing list task
    async def do_mailing_list_check():
        if not email:
            return None
        return await check_mailing_lists(email)
    tasks.append(do_mailing_list_check())

    # Execute all concurrently
    username_results, password_res, email_res, domain_res, mailing_res = await asyncio.gather(*tasks)

    # Filter & sort username results
    found_profiles = [p for p in username_results if p.get("exists")]
    # Sort: high match confidence first, then platform name
    def sort_key(p):
        conf = p.get("match", {}).get("confidence", "")
        if conf == "high": return 0
        if conf == "medium": return 1
        return 2
    found_profiles.sort(key=sort_key)

    # Phone Recon (fast sync)
    phone_res = analyze_phone_number(phone) if phone else None

    # Dorks (fast sync)
    dorks = generate_dorks(
        name=name,
        city=city,
        company=employer,
        username=username,
        email=email
    )

    # Aggregated Summary Stats
    summary = {
        "profiles_checked": len(username_results),
        "profiles_found": len(found_profiles),
        "high_confidence_matches": len([p for p in found_profiles if p.get("match", {}).get("confidence") in ["high", "medium"]]),
        "password_pwned": password_res.get("data", {}).get("pwned") if password_res and password_res.get("success") else None,
        "password_breach_count": password_res.get("data", {}).get("count") if password_res and password_res.get("success") else 0,
        "email_breached": email_res.get("data", {}).get("breached") if email_res and email_res.get("success") else None,
        "email_breach_count": email_res.get("data", {}).get("breach_count", 0) if email_res and email_res.get("success") else 0,
        "domain_spf_status": domain_res.get("data", {}).get("email_security", {}).get("spf", {}).get("status") if domain_res and domain_res.get("success") else None,
        "domain_dmarc_status": domain_res.get("data", {}).get("email_security", {}).get("dmarc", {}).get("status") if domain_res and domain_res.get("success") else None,
        "exposure_score": identity_audit.get("data", {}).get("exposure_score", 0),
        "exposure_level": identity_audit.get("data", {}).get("exposure_level", "GERING"),
        "badge_color": identity_audit.get("data", {}).get("badge_color", "emerald")
    }

    # Adjust Exposure Score if real leaks were detected
    if summary["password_pwned"]:
        summary["exposure_score"] = min(100, summary["exposure_score"] + 30)
        summary["exposure_level"] = "KRITISCH"
        summary["badge_color"] = "rose"

    return {
        "success": True,
        "summary": summary,
        "identity_audit": identity_audit.get("data", {}),
        "found_profiles": found_profiles,
        "password_result": password_res.get("data") if password_res and password_res.get("success") else None,
        "email_result": email_res.get("data") if email_res and email_res.get("success") else None,
        "mailing_list_result": mailing_res.get("data") if mailing_res and mailing_res.get("success") else None,
        "domain_result": domain_res.get("data") if domain_res and domain_res.get("success") else None,
        "phone_result": phone_res,
        "dorks": dorks
    }
