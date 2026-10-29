from typing import Dict, Any, List
from app.modules.email_permutator import generate_email_permutations
from app.modules.phone_recon import analyze_phone_number
from app.modules.dork_builder import generate_dorks

def audit_identity_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates multi-attribute identity inputs to calculate the overall footprint exposure,
    threat vectors, generated permutations and GDPR removal tools.
    """
    full_name = data.get("full_name", "").strip()
    usernames = [u.strip() for u in data.get("usernames", []) if u.strip()]
    cities = [c.strip() for c in data.get("cities", []) if c.strip()]
    employers = [e.strip() for e in data.get("employers", []) if e.strip()]
    emails = [em.strip() for em in data.get("emails", []) if em.strip()]
    phones = [p.strip() for p in data.get("phones", []) if p.strip()]
    keywords = [k.strip() for k in data.get("keywords", []) if k.strip()]

    # Threat vectors and risk score calculation
    score = 0
    threat_vectors = []
    
    if full_name:
        score += 20
        if cities:
            score += 25
            threat_vectors.append({
                "severity": "HIGH",
                "title": "Verknüpfung Name + Wohnort",
                "desc": f"Die Kombination aus '{full_name}' und '{', '.join(cities)}' ermöglicht die exakte Identifikation deiner Person und führt häufig zu privaten Meldeadressen oder Telefonbucheinträgen."
            })
        if employers:
            score += 20
            threat_vectors.append({
                "severity": "MEDIUM",
                "title": "Social Engineering & Spear Phishing",
                "desc": f"Durch die Bekanntheit deines Arbeitgebers '{', '.join(employers)}' können Angreifer gezielte Business-Phishing-Mails verfassen."
            })

    if phones:
        score += 25
        threat_vectors.append({
            "severity": "CRITICAL",
            "title": "Offengelegte Rufnummer",
            "desc": "Eine öffentlich auffindbare Handynummer birgt Risiken für Smishing (SMS-Phishing), Messenger-Stalking und SIM-Swapping-Angriffe."
        })

    if emails:
        score += 15

    # Email Permutations
    email_permutations = []
    if full_name:
        parts = full_name.split()
        if len(parts) >= 2:
            fn, ln = parts[0], parts[-1]
            custom_dom = ""
            if employers and "." in employers[0]:
                custom_dom = employers[0]
            email_permutations = generate_email_permutations(fn, ln, custom_domain=custom_dom)[:12]

    # Phone Analysis
    phone_analyses = [analyze_phone_number(p) for p in phones]

    # Dorks correlated with identity
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

    # Risk level determination
    score = min(score, 100)
    if score >= 75:
        level = "KRITISCH"
        color = "rose"
    elif score >= 50:
        level = "HOCH"
        color = "amber"
    elif score >= 25:
        level = "MODERAT"
        color = "yellow"
    else:
        level = "GERING"
        color = "emerald"

    # GDPR Deletion Template (DSGVO Art. 17 Recht auf Vergessenwerden)
    gdpr_template = f"""Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Löschung („Recht auf Vergessenwerden“) gemäß Art. 17 DSGVO Gebrauch.

Bitte löschen Sie unverzüglich alle personenbezogenen Daten, die zu meiner Person ({full_name or '[Dein Name]'}) gespeichert sind oder öffentlich im Index bereitgestellt werden.

Falls Sie die Daten an Dritte übermittelt haben, sind Sie nach Art. 17 Abs. 2 DSGVO verpflichtet, auch diese über mein Löschbegehren zu unterrichten.

Bitte bestätigen Sie mir die unverzügliche Löschung schriftlich.

Mit freundlichen Grüßen,
{full_name or '[Dein Name]'}"""

    return {
        "success": True,
        "data": {
            "exposure_score": score,
            "exposure_level": level,
            "badge_color": color,
            "threat_vectors": threat_vectors,
            "email_permutations": email_permutations,
            "phone_analyses": phone_analyses,
            "dorks": dorks,
            "gdpr_template": gdpr_template,
            "google_removal_url": "https://support.google.com/websearch/troubleshooter/3111061"
        }
    }
