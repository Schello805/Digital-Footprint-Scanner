from typing import Dict, Any, List, Optional
from app.modules.phone_recon import analyze_phone_number
from app.modules.dork_builder import generate_dorks

def audit_identity_profile(
    data: Dict[str, Any],
    scan_results: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Audits the target digital footprint strictly based on FACTS and verified scan evidence.
    No assumptions, no arbitrary risk points for unverified inputs.
    """
    full_name = data.get("full_name", "").strip()
    usernames = [u.strip() for u in data.get("usernames", []) if u.strip()]
    cities = [c.strip() for c in data.get("cities", []) if c.strip()]
    employers = [e.strip() for e in data.get("employers", []) if e.strip()]
    emails = [em.strip() for em in data.get("emails", []) if em.strip()]
    phones = [p.strip() for p in data.get("phones", []) if p.strip()]

    score = 0
    threat_vectors = []

    # 1. Fact-based assessment from verified scan evidence
    if scan_results:
        # A. Password breach fact
        pwd_res = scan_results.get("password_result")
        if pwd_res and pwd_res.get("pwned"):
            cnt = pwd_res.get("count", 0)
            score += 35
            threat_vectors.append({
                "severity": "CRITICAL",
                "title": "Passwort in bekannten Datenpannen öffentlich kompromittiert",
                "title_en": "Password compromised in public data breaches",
                "desc": f"Verifizierter Fakt: Das geprüfte Passwort taucht {cnt:,} Mal in geleakten Datenbanken (HaveIBeenPwned k-Anonymity) auf.",
                "desc_en": f"Verified fact: The tested password appears {cnt:,} times in leaked databases (HaveIBeenPwned k-Anonymity)."
            })

        # B. Email breach fact
        email_res = scan_results.get("email_result")
        if email_res and email_res.get("breached"):
            b_count = email_res.get("breach_count", 0)
            b_names = email_res.get("breach_names", [])
            score += min(35, b_count * 10)
            names_preview = ", ".join(b_names[:4])
            threat_vectors.append({
                "severity": "HIGH",
                "title": f"E-Mail in {b_count} bestätigten Datenpannen registriert",
                "title_en": f"Email registered in {b_count} confirmed data breaches",
                "desc": f"Verifizierter Fakt: Folgende Sicherheitsvorfälle betreffen diese Adresse: {names_preview}.",
                "desc_en": f"Verified fact: Confirmed security incidents affecting this address: {names_preview}."
            })

        # C. Domain SPF/DMARC spoofing vulnerability fact
        dom_res = scan_results.get("domain_result")
        if dom_res and dom_res.get("email_security"):
            spf_status = dom_res["email_security"].get("spf", {}).get("status")
            dmarc_status = dom_res["email_security"].get("dmarc", {}).get("status")
            if spf_status == "missing" or dmarc_status == "missing":
                score += 20
                threat_vectors.append({
                    "severity": "MEDIUM",
                    "title": "Fehlender DNS-Schutz vor E-Mail-Identitätsdiebstahl (Spoofing)",
                    "title_en": "Missing DNS spoofing protection for personal domain",
                    "desc": "Verifizierter Fakt: Die autoritativen DNS-Einträge der Domain weisen keinen SPF- oder DMARC-Schutz auf. Fremde können E-Mails im Namen dieser Domain versenden.",
                    "desc_en": "Verified fact: Authoritative DNS records lack SPF or DMARC protection. Third parties can forge emails using this domain."
                })

        # D. Verified profile matches (facts where name/city appears in public profile)
        found_profiles = scan_results.get("found_profiles", [])
        verified_profiles = [p for p in found_profiles if p.get("match", {}).get("confidence") in ["high", "medium"]]
        if verified_profiles:
            score += min(20, len(verified_profiles) * 5)
            plat_names = ", ".join([p["platform"] for p in verified_profiles[:4]])
            threat_vectors.append({
                "severity": "MEDIUM",
                "title": f"{len(verified_profiles)} öffentlich bestätigte Benutzerkonten",
                "title_en": f"{len(verified_profiles)} publicly confirmed online accounts",
                "desc": f"Verifizierter Fakt: Öffentliche Profile mit Namens- oder Ortsübereinstimmung gefunden auf: {plat_names}.",
                "desc_en": f"Verified fact: Public profiles with verified name or location match found on: {plat_names}."
            })

    # Phone analysis strictly based on official ITU/BNetzA numbering plan
    phone_analyses = [analyze_phone_number(p) for p in phones]

    # Google Dorks for direct register search
    first_user = usernames[0] if usernames else ""
    first_city = cities[0] if cities else ""
    first_emp = employers[0] if employers else ""
    first_mail = emails[0] if emails else ""
    
    dorks = generate_dorks(
        name=full_name,
        city=first_city,
        company=first_emp,
        username=first_user,
        email=first_mail
    )

    # Risk level determination strictly based on factual exposure
    score = min(score, 100)
    if score >= 70:
        level = "KRITISCH"
        color = "rose"
    elif score >= 40:
        level = "HOCH"
        color = "amber"
    elif score >= 20:
        level = "MODERAT"
        color = "yellow"
    else:
        level = "GERING"
        color = "emerald"

    # GDPR Deletion Templates (EN & DE)
    gdpr_template_de = f"""Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Löschung („Recht auf Vergessenwerden“) gemäß Art. 17 DSGVO Gebrauch.

Bitte löschen Sie unverzüglich alle personenbezogenen Daten, die zu meiner Person ({full_name or '[Dein Name]'}) gespeichert sind oder öffentlich im Index bereitgestellt werden.

Falls Sie die Daten an Dritte übermittelt haben, sind Sie nach Art. 17 Abs. 2 DSGVO verpflichtet, auch diese über mein Löschbegehren zu unterrichten.

Bitte bestätigen Sie mir die unverzügliche Löschung schriftlich.

Mit freundlichen Grüßen,
{full_name or '[Dein Name]'}"""

    gdpr_template_en = f"""To Whom It May Concern,

I am writing to exercise my right to erasure ('Right to be Forgotten') pursuant to Article 17 of the General Data Protection Regulation (GDPR) / applicable privacy legislation.

Please permanently delete and erase all personal data pertaining to me ({full_name or '[Your Name]'}) stored in your databases, public directories, and web indexes without undue delay.

If you have made this personal data public or disclosed it to third parties, please inform them of this erasure request as required by law.

Please confirm the execution of this deletion in writing.

Sincerely,
{full_name or '[Your Name]'}"""

    return {
        "success": True,
        "data": {
            "exposure_score": score,
            "exposure_level": level,
            "badge_color": color,
            "threat_vectors": threat_vectors,
            "phone_analyses": phone_analyses,
            "dorks": dorks,
            "gdpr_template": gdpr_template_en,
            "gdpr_template_de": gdpr_template_de,
            "gdpr_template_en": gdpr_template_en,
            "google_removal_url": "https://support.google.com/websearch/troubleshooter/3111061"
        }
    }
