import asyncio
import urllib.parse
from typing import Dict, Any, Optional, List
from app.modules.username_checker import scan_usernames_fast
from app.modules.breach_checker import check_password_pwned, check_email_breach
from app.modules.domain_recon import (
    check_domain_dns,
    probe_personal_websites,
    discover_infrastructure_and_projects,
    parse_domain_target
)
from app.modules.phone_recon import analyze_phone_number
from app.modules.mailing_list_checker import check_mailing_lists
from app.modules.email_account_checker import check_email_accounts
from app.modules.dork_builder import generate_dorks
from app.modules.identity_auditor import audit_identity_profile
from app.modules.cleanup_guide import get_remediation_guide
from app.modules.image_recon import collect_discovered_images
from app.modules.security_intel import check_infostealer_malware, check_pgp_keyserver
from app.modules.live_web_search import search_web_with_entity_filter
from app.config import settings

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "web.de", "gmx.de", "gmx.net", "gmx.at", "gmx.ch",
    "outlook.com", "outlook.de", "hotmail.com", "hotmail.de", "yahoo.com", "yahoo.de",
    "icloud.com", "me.com", "mac.com", "t-online.de", "freenet.de", "posteo.de",
    "proton.me", "protonmail.com", "mail.de", "arcor.de", "1und1.de", "live.com"
}

def generate_web_directories(
    name: str = "",
    username: str = "",
    email: str = "",
    city: str = "",
    employer: str = "",
    domain: str = ""
) -> List[Dict[str, Any]]:
    """
    Generates a curated list of public websites, directories, and registries
    where the target person appears or is publicly indexed.
    """
    dirs = []
    clean_name = name.strip()
    target_q = f'"{clean_name}"' if clean_name else (f'"{username.strip()}"' if username.strip() else "")
    if not target_q and email:
        target_q = f'"{email.strip()}"'
        
    if not target_q:
        return []

    # 1. Google Webindex
    dirs.append({
        "site": "Google Webindex",
        "icon": "🌐",
        "category": "Suchmaschinen-Index",
        "query": target_q,
        "desc": f"Alle indexierten Webseiten und Fundstellen für {clean_name or target_q}",
        "url": f"https://www.google.com/search?q={urllib.parse.quote(target_q)}"
    })

    # 2. LinkedIn
    dirs.append({
        "site": "LinkedIn",
        "icon": "💼",
        "category": "Berufs- & Karriereprofil",
        "query": f"site:linkedin.com/in/ {target_q}",
        "desc": "Öffentlich indexierte Profile, berufliche Stationen und Arbeitgeber",
        "url": f"https://www.google.com/search?q={urllib.parse.quote(f'site:linkedin.com/in/ {target_q}')}"
    })

    # 3. XING
    dirs.append({
        "site": "XING",
        "icon": "👥",
        "category": "Business-Netzwerk DACH",
        "query": f"site:xing.com/profile/ {target_q}",
        "desc": "Öffentliche Profile im deutschsprachigen Wirtschaftsraum",
        "url": f"https://www.google.com/search?q={urllib.parse.quote(f'site:xing.com/profile/ {target_q}')}"
    })

    # 4. North Data
    if clean_name:
        dirs.append({
            "site": "North Data",
            "icon": "🏢",
            "category": "Handelsregister & Wirtschaft",
            "query": f"northdata.de?q={clean_name}",
            "desc": "Offizielle Firmendaten, Gesellschafter, Geschäftsführungen und Bilanzen",
            "url": f"https://www.northdata.de?q={urllib.parse.quote(clean_name)}"
        })

    # 5. Bundesanzeiger & Unternehmensregister
    if clean_name:
        dirs.append({
            "site": "Unternehmensregister / Bundesanzeiger",
            "icon": "🏛️",
            "category": "Amtliche Bekanntmachungen",
            "query": f"(site:unternehmensregister.de OR site:bundesanzeiger.de) {target_q}",
            "desc": "Offizielle Bekanntmachungen, Gesellschafterlisten und Firmenverflechtungen",
            "url": f"https://www.google.com/search?q={urllib.parse.quote(f'(site:unternehmensregister.de OR site:bundesanzeiger.de) {target_q}')}"
        })

    # 6. Das Örtliche / Telefonbuch
    if clean_name:
        loc_param = f"&ci={urllib.parse.quote(city.strip())}" if city.strip() else ""
        dirs.append({
            "site": "Das Örtliche / Telefonbuch",
            "icon": "📖",
            "category": "Telefon- & Adressverzeichnis",
            "query": f"{clean_name} {city.strip()}".strip(),
            "desc": "Öffentlich geführte Telefonnummern, Anschriften und Festnetzdaten",
            "url": f"https://www.dasoertliche.de/?zvo_ok=0&bu_ok=0&form_name=search_nat&kw={urllib.parse.quote(clean_name)}{loc_param}"
        })

    # 7. Eigene Website (nur wenn keine allgemeine Freemail-Domain)
    if domain:
        clean_dom = domain.strip().lower()
        if clean_dom.startswith("http://"): clean_dom = clean_dom[7:]
        if clean_dom.startswith("https://"): clean_dom = clean_dom[8:]
        clean_dom = clean_dom.split("/")[0]
        if clean_dom and clean_dom not in FREEMAIL_DOMAINS:
            dirs.insert(1, {
                "site": f"Eigene Website ({clean_dom})",
                "icon": "🌐",
                "category": "Persönlicher Web-Auftritt",
                "query": f"https://{clean_dom}",
                "desc": f"Direkte Domain https://{clean_dom}",
                "url": f"https://{clean_dom}"
            })

    return dirs

async def execute_full_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a comprehensive, orchestrated 1-click audit across all OSINT footprint vectors concurrently.
    All scores and assessments are strictly derived from verified facts.
    If an email is provided without a username, automatically performs cryptographic Gravatar OSINT
    to discover connected online handles (@schello805), verified locations, and linked accounts (Duolingo, etc.).
    """
    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    name = data.get("name", "").strip()
    if not name:
        if first_name or last_name:
            name = f"{first_name} {last_name}".strip()
    elif not first_name:
        parts = name.split()
        first_name = parts[0]
        last_name = " ".join(parts[1:]) if len(parts) > 1 else ""
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    domain = data.get("domain", "").strip()
    phone = data.get("phone", "").strip()
    city = data.get("city", "").strip()
    employer = data.get("employer", "").strip()
    raw_keywords = data.get("keywords", "")
    
    keywords = [k.strip() for k in raw_keywords.split(",") if k.strip()] if isinstance(raw_keywords, str) else (raw_keywords or [])

    # Determine effective target domain / URL
    target_domain_input = domain
    if not target_domain_input and email and "@" in email:
        email_dom = email.split("@")[1].strip().lower()
        if email_dom not in FREEMAIL_DOMAINS:
            target_domain_input = email_dom

    # Early Email-to-Identity Resolution (Gravatar, Duolingo, etc.)
    email_recon_res = None
    discovered_handle = None
    if email:
        email_recon_res = await check_email_accounts(email)
        disc_users = email_recon_res.get("discovered_usernames", [])
        if disc_users:
            discovered_handle = disc_users[0]
            # If no username provided or username was set to email, adopt discovered handle
            if not username or "@" in username:
                username = discovered_handle
        # Enrich location if missing
        if not city and email_recon_res.get("discovered_location"):
            city = email_recon_res.get("discovered_location")
        # Enrich name if missing
        if not name and email_recon_res.get("discovered_name") and email_recon_res.get("discovered_name") != discovered_handle:
            name = email_recon_res.get("discovered_name")

    # Prepare Async Tasks
    tasks = []

    # Username task
    async def do_username_scan():
        if not username:
            return []
        ctx = {"name": name, "city": city, "employer": employer, "keywords": keywords}
        res = await scan_usernames_fast(username, context=ctx)
        # Check dotless/normalized variant if dots exist (e.g. michael.schellenberger -> michaelschellenberger)
        if "." in username:
            alt_user = username.replace(".", "")
            if alt_user and alt_user != username:
                alt_res = await scan_usernames_fast(alt_user, context=ctx)
                existing_urls = {p.get("url") for p in res if p.get("exists")}
                for p in alt_res:
                    if p.get("exists") and p.get("url") not in existing_urls:
                        res.append(p)
                        existing_urls.add(p.get("url"))
        return res
    tasks.append(do_username_scan())

    # Password task
    async def do_password_check():
        if not password:
            return None
        return await check_password_pwned(password)
    tasks.append(do_password_check())

    # Email breach task (XON / HIBP)
    async def do_email_check():
        if not email:
            return None
        return await check_email_breach(email, api_key=settings.hibp_api_key)
    tasks.append(do_email_check())

    # Domain task (sync function, run in executor)
    async def do_domain_check():
        if not target_domain_input:
            return None
        loop = asyncio.get_event_loop()
        parsed = parse_domain_target(target_domain_input)
        return await loop.run_in_executor(None, check_domain_dns, parsed["apex"])
    tasks.append(do_domain_check())

    # Personal Website & Subdomain Probe task
    async def do_personal_probe():
        if not target_domain_input:
            return []
        return await probe_personal_websites(
            target_domain_input,
            first_name=first_name,
            last_name=last_name,
            username=username
        )
    tasks.append(do_personal_probe())

    # Infrastructure & Co-Hosted Web Projects task
    async def do_infra_recon():
        if not target_domain_input:
            return None
        return await discover_infrastructure_and_projects(target_domain_input)
    tasks.append(do_infra_recon())

    # Mailing list task
    async def do_mailing_list_check():
        if not email:
            return None
        return await check_mailing_lists(email)
    tasks.append(do_mailing_list_check())

    # Infostealer Malware task (Hudson Rock Cybercrime DB)
    async def do_infostealer_check():
        if not email:
            return None
        return await check_infostealer_malware(email)
    tasks.append(do_infostealer_check())

    # OpenPGP Keyserver task (Ubuntu Keyserver)
    async def do_pgp_check():
        if not email:
            return None
        return await check_pgp_keyserver(email)
    tasks.append(do_pgp_check())

    # Live Web Search with Smart Entity Filter task
    async def do_live_web_search():
        if not name and not username:
            return []
        return await search_web_with_entity_filter(
            name=name,
            city=city,
            employer=employer,
            domain=target_domain_input,
            username=username,
            keywords=keywords
        )
    tasks.append(do_live_web_search())

    # Execute all concurrently
    username_results, password_res, email_res, domain_res, personal_sites_res, infra_res, mailing_res, infostealer_res, pgp_res, live_web_res = await asyncio.gather(*tasks)

    # Filter & sort username results
    found_profiles = [p for p in username_results if p.get("exists")]
    
    # Merge direct email-registered accounts (e.g. Duolingo) into discovered profiles if not already present
    if email_recon_res and email_recon_res.get("registered_accounts"):
        existing_urls = {p.get("url") for p in found_profiles}
        for acc in email_recon_res["registered_accounts"]:
            if acc.get("profile_url") and acc["profile_url"] not in existing_urls:
                found_profiles.append({
                    "platform": acc["service"],
                    "category": acc["category"],
                    "url": acc["profile_url"],
                    "exists": True,
                    "status": "found",
                    "snippet": f"{acc['evidence']} ({email})",
                    "match": {
                        "score": 100,
                        "matches": ["E-Mail-Verifikation"],
                        "confidence": "high"
                    }
                })
                existing_urls.add(acc["profile_url"])

    # Merge verified web search results into found_profiles (e.g. LinkedIn, Xing, North Data)
    if live_web_res:
        existing_profile_urls = {p.get("url") for p in found_profiles}
        for hit in live_web_res:
            hit_url = hit.get("url", "")
            if hit_url and hit_url not in existing_profile_urls:
                cat = "Web-Erwähnung"
                plat = "Webseite"
                if "linkedin.com" in hit_url:
                    plat = "LinkedIn"
                    cat = "Berufs- & Karriereprofil"
                elif "xing.com" in hit_url:
                    plat = "Xing"
                    cat = "Berufs- & Karriereprofil"
                elif "northdata.de" in hit_url or "companyhouse.de" in hit_url:
                    plat = "Handelsregister / Wirtschaft"
                    cat = "Wirtschaft & Firmenregister"

                matched_sig_str = ", ".join(hit.get("matched_signals", []))
                found_profiles.append({
                    "platform": plat,
                    "category": cat,
                    "url": hit_url,
                    "exists": True,
                    "status": "found",
                    "snippet": f"{hit['title']} (Verifiziert: {matched_sig_str})",
                    "match": {
                        "score": 95,
                        "matches": [f"Kontext: {matched_sig_str}"],
                        "confidence": "high"
                    }
                })
                existing_profile_urls.add(hit_url)

    def sort_key(p):
        conf = p.get("match", {}).get("confidence", "")
        if conf == "high": return 0
        if conf == "medium": return 1
        return 2
    found_profiles.sort(key=sort_key)

    # Insert verified personal website(s) or provided domain into found_profiles
    if personal_sites_res:
        for site in reversed(personal_sites_res):
            found_profiles.insert(0, {
                "platform": f"Website ({site.get('host') or site.get('domain')})",
                "category": "Eigene Web-Präsenz",
                "url": site["url"],
                "exists": True,
                "status": "found",
                "snippet": site["title"],
                "match": {
                    "score": 100,
                    "matches": ["Verifizierte persönliche Website", f"HTTP {site.get('status', 200)} OK"],
                    "confidence": "high"
                }
            })
    elif target_domain_input:
        parsed = parse_domain_target(target_domain_input)
        clean_dom = parsed["apex"]
        if clean_dom and clean_dom not in FREEMAIL_DOMAINS:
            dom_url = parsed["exact_url"] or f"https://{clean_dom}"
            found_profiles.insert(0, {
                "platform": f"Website ({parsed['host'] or clean_dom})",
                "category": "Eigene Web-Präsenz",
                "url": dom_url,
                "exists": True,
                "status": "found",
                "snippet": f"Offizielle Domain ({name or clean_dom})",
                "match": {
                    "score": 100,
                    "matches": ["Eigene Domain / DNS"],
                    "confidence": "high"
                }
            })

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

    # Curated Web Directories & Public Appearances
    web_directories = generate_web_directories(
        name=name,
        username=username,
        email=email,
        city=city,
        employer=employer,
        domain=domain
    )

    # Remediation & Cleanup Guide
    remediation_guide = get_remediation_guide(found_profiles, name=name, email=email)

    # Factual Evidence-based Exposure Audit
    id_data = {
        "full_name": name,
        "usernames": [username] if username else [],
        "cities": [city] if city else [],
        "employers": [employer] if employer else [],
        "emails": [email] if email else [],
        "phones": [phone] if phone else [],
        "keywords": keywords
    }
    
    scan_results = {
        "password_result": password_res.get("data") if password_res and password_res.get("success") else None,
        "email_result": email_res.get("data") if email_res and email_res.get("success") else None,
        "domain_result": domain_res.get("data") if domain_res and domain_res.get("success") else None,
        "found_profiles": found_profiles,
        "phone_result": phone_res,
        "mailing_result": mailing_res.get("data") if mailing_res and mailing_res.get("success") else None
    }
    
    identity_audit = audit_identity_profile(id_data, scan_results=scan_results)
    audit_data = identity_audit.get("data", {})

    # Aggregated Summary Stats (All strictly verified facts)
    high_matches = len([p for p in found_profiles if p.get("match", {}).get("confidence") in ["high", "medium"]])
    summary = {
        "profiles_found": len(found_profiles),
        "high_confidence_matches": high_matches,
        "unverified_handles": len(found_profiles) - high_matches,
        "discovered_handle": discovered_handle,
        "discovered_location": email_recon_res.get("discovered_location") if email_recon_res else None,
        "password_pwned": password_res.get("data", {}).get("pwned") if password_res and password_res.get("success") else None,
        "password_breach_count": password_res.get("data", {}).get("count") if password_res and password_res.get("success") else 0,
        "email_breached": email_res.get("data", {}).get("breached") if email_res and email_res.get("success") else None,
        "email_breach_count": email_res.get("data", {}).get("breach_count", 0) if email_res and email_res.get("success") else 0,
        "infostealer_infected": infostealer_res.get("infected", False) if infostealer_res else False,
        "infostealer_count": infostealer_res.get("stealers_count", 0) if infostealer_res else 0,
        "pgp_has_key": pgp_res.get("has_pgp", False) if pgp_res else False,
        "cohosted_count": len(infra_res.get("cohosted_domains", [])) if infra_res and infra_res.get("checked") else 0,
        "server_ip": infra_res.get("server_ip") if infra_res else None,
        "domain_spf_status": domain_res.get("data", {}).get("email_security", {}).get("spf", {}).get("status") if domain_res and domain_res.get("success") else None,
        "domain_dmarc_status": domain_res.get("data", {}).get("email_security", {}).get("dmarc", {}).get("status") if domain_res and domain_res.get("success") else None,
        "exposure_score": audit_data.get("exposure_score", 0),
        "exposure_level": audit_data.get("exposure_level", "GERING"),
        "badge_color": audit_data.get("badge_color", "emerald")
    }

    # Infostealer Malware Alert in Threat Vectors
    if infostealer_res and infostealer_res.get("infected"):
        fam_str = ", ".join(infostealer_res.get("families", [])) or "Trojaner"
        audit_data.setdefault("threat_vectors", []).insert(0, {
            "title": f"Kritisch: Infostealer-Malware Infektion ({fam_str})",
            "title_en": f"Critical: Infostealer Malware Infection ({fam_str})",
            "severity": "CRITICAL",
            "desc": f"Ein oder mehrere Computer, auf denen {email} angemeldet war, wurden durch Cyberkriminelle mit Infostealer-Malware infiziert. Gespeicherte Passwörter & Sessions wurden abgegriffen.",
            "desc_en": f"One or more computers authenticated with {email} were infected by infostealer trojans leaking browser passwords & sessions to cybercriminals."
        })
        audit_data["exposure_score"] = min(100, audit_data.get("exposure_score", 0) + 35)
        audit_data["exposure_level"] = "KRITISCH"
        audit_data["badge_color"] = "rose"
        summary["exposure_score"] = audit_data["exposure_score"]
        summary["exposure_level"] = audit_data["exposure_level"]
        summary["badge_color"] = audit_data["badge_color"]

    # If OpenPGP Key found on Ubuntu / MIT keyserver, insert as verified crypto identity
    if pgp_res and pgp_res.get("has_pgp"):
        keys_str = ", ".join(pgp_res.get("keys", []))
        found_profiles.insert(0, {
            "platform": "OpenPGP Key Server (Ubuntu)",
            "category": "Kryptografie & PGP",
            "url": pgp_res.get("lookup_url", "https://keyserver.ubuntu.com"),
            "exists": True,
            "status": "found",
            "snippet": f"{pgp_res.get('key_count')} verifizierter PGP-Schlüssel ({keys_str[:24]}...)",
            "match": {
                "score": 100,
                "matches": ["Kryptografische PGP E-Mail-Signatur"],
                "confidence": "high"
            }
        })
        summary["profiles_found"] = len(found_profiles)
        summary["high_confidence_matches"] += 1

    # Collect and aggregate all discovered images & avatars
    session_avatar = data.get("session_avatar") or data.get("avatar_url")
    discovered_images = collect_discovered_images(
        email_recon_res=email_recon_res,
        found_profiles=found_profiles,
        session_avatar=session_avatar,
        email=email,
        username=username or discovered_handle
    )
    
    primary_avatar = email_recon_res.get("avatar_url") if (email_recon_res and email_recon_res.get("avatar_url")) else None
    if not primary_avatar and discovered_images:
        primary_avatar = discovered_images[0]["url"]

    return {
        "success": True,
        "summary": summary,
        "identity_audit": audit_data,
        "found_profiles": found_profiles,
        "avatar_url": primary_avatar,
        "discovered_images": discovered_images,
        "email_accounts": email_recon_res.get("registered_accounts", []) if email_recon_res else [],
        "discovered_handle": discovered_handle,
        "resolved_username": username,
        "resolved_city": city,
        "resolved_name": name,
        "password_result": password_res.get("data") if password_res and password_res.get("success") else None,
        "email_result": email_res.get("data") if email_res and email_res.get("success") else None,
        "infostealer_result": infostealer_res,
        "pgp_result": pgp_res,
        "mailing_list_result": mailing_res.get("data") if mailing_res and mailing_res.get("success") else None,
        "domain_result": domain_res.get("data") if domain_res and domain_res.get("success") else None,
        "infra_result": infra_res,
        "personal_sites": personal_sites_res,
        "live_web_results": live_web_res,
        "phone_result": phone_res,
        "dorks": dorks,
        "web_directories": web_directories,
        "remediation_guide": remediation_guide
    }
