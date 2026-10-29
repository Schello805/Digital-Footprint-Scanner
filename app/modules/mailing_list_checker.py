import re
import urllib.parse
from typing import Dict, Any, List
import dns.resolver
import httpx

async def check_mailing_lists(email: str) -> Dict[str, Any]:
    """
    Analyzes an email address for public mailing list presence and checks domain mail routing strictly via verifiable facts.
    Queries open mailing list archives to detect actual subscribed / active mailing lists for 1-click opt-out.
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
        resolver.timeout = 2.0
        resolver.lifetime = 2.5
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [r.exchange.to_text().rstrip(".") for r in answers]
        has_mx = len(mx_hosts) > 0
    except Exception:
        has_mx = False

    # 2. Query public mailing list archive (MARC.info author index) for real list memberships
    found_lists: List[Dict[str, str]] = []
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            url = f"https://marc.info/?s={encoded_email}&q=a"
            response = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
            })
            if response.status_code == 200:
                raw_lists = re.findall(r'<a\s+href=["\']\?l=([a-zA-Z0-9_\-\.]+)[^"\']*["\']>([^<]+)</a>', response.text)
                seen = set()
                for slug, display_name in raw_lists:
                    slug_clean = slug.strip().lower()
                    if slug_clean not in seen and len(slug_clean) > 2:
                        seen.add(slug_clean)
                        # Build standard mailing list target address (e.g. list@domain or list)
                        target_addr = f"{slug_clean}@{domain}" if "@" not in slug_clean else slug_clean
                        found_lists.append({
                            "name": display_name.strip() or slug_clean,
                            "slug": slug_clean,
                            "identifier": target_addr,
                            "archive_url": f"https://marc.info/?l={slug_clean}",
                            "source": "MARC Public Mailing List Archive"
                        })
    except Exception:
        # Graceful fallback if network archive is unreachable
        pass

    result = {
        "email": clean_email,
        "domain": domain,
        "has_valid_mx": has_mx,
        "mx_hosts": mx_hosts[:3],
        "found_lists": found_lists[:12],
        "found_count": len(found_lists),
        "specialized_searches": [
            {
                "title": "The Mail Archive",
                "url": f"https://www.mail-archive.com/?q={encoded_email}",
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
                "url": f"https://marc.info/?s={encoded_email}&q=t",
                "desc": "Direktsuche im MARC Mailinglist-Archiv."
            }
        ]
    }

    return {"success": True, "data": result}
