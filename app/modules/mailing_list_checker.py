import re
import urllib.parse
from typing import Dict, Any, List
import dns.resolver

def check_mailing_lists(email: str) -> Dict[str, Any]:
    """
    Analyzes an email address for public mailing list presence and checks domain mail routing strictly via verifiable facts.
    Provides targeted precision archive query URLs.
    """
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        return {"success": False, "error": "Ungültige E-Mail-Adresse für Mailinglisten-Check"}

    domain = clean_email.split("@")[1]
    encoded_email = urllib.parse.quote_plus(clean_email)

    # 1. Check MX records of the email domain (Verifiable DNS fact)
    has_mx = False
    mx_hosts: List[str] = []
    try:
        try:
            resolver = dns.resolver.Resolver()
        except Exception:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = 2.5
        resolver.lifetime = 3.0
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [r.exchange.to_text().rstrip(".") for r in answers]
        has_mx = len(mx_hosts) > 0
    except Exception:
        has_mx = False

    result = {
        "email": clean_email,
        "domain": domain,
        "has_valid_mx": has_mx,
        "mx_hosts": mx_hosts[:3],
        "specialized_searches": [
            {
                "title": "The Mail Archive",
                "url": f"https://www.mail-archive.com/search?q={encoded_email}",
                "desc": "Durchsucht archivierte E-Mails aus weltweiten Diskussionslisten."
            },
            {
                "title": "GNU Mailman & Pipermail Archive",
                "url": f'https://www.google.com/search?q=inurl:pipermail+"{encoded_email}"',
                "desc": "Sucht in offenen GNU-Mailman-Archiven von Vereinen, Universitäten und Open-Source-Projekten."
            },
            {
                "title": "Google Groups (Foren & Usenet)",
                "url": f'https://groups.google.com/search?q={encoded_email}',
                "desc": "Öffentliche Google Groups und Usenet-Archive."
            },
            {
                "title": "MARC.info Archive",
                "url": f"https://marc.info/?s={encoded_email}",
                "desc": "Direktsuche im MARC Mailinglist-Archiv."
            }
        ]
    }

    return {"success": True, "data": result}
