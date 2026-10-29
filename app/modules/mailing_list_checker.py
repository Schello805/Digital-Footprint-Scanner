import re
import urllib.parse
import httpx
from typing import Dict, Any, List

async def check_mailing_lists(email: str) -> Dict[str, Any]:
    """
    Checks if an email address appears in public mailing lists and archives (GNU Mailman, Pipermail, MARC, etc.).
    """
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        return {"success": False, "error": "Ungültige E-Mail-Adresse für Mailinglisten-Check"}

    encoded_email = urllib.parse.quote_plus(clean_email)
    
    result = {
        "email": clean_email,
        "found_in_marc": False,
        "marc_hit_count": 0,
        "detected_lists": [],
        "marc_url": f"https://marc.info/?s={encoded_email}",
        "specialized_searches": [
            {
                "title": "The Mail Archive (Mailinglisten-Suchmaschine)",
                "url": f"https://www.mail-archive.com/search?q={encoded_email}",
                "desc": "Durchsucht Millionen archivierter E-Mails aus Tausenden weltweiter Diskussionslisten."
            },
            {
                "title": "GNU Mailman & Pipermail Archive",
                "url": f'https://www.google.com/search?q=inurl:pipermail+"{encoded_email}"',
                "desc": "Sucht in offenen GNU-Mailman-Archiven von Vereinen, Universitäten und Open-Source-Projekten."
            },
            {
                "title": "Google Groups (Foren & Listen)",
                "url": f'https://groups.google.com/search?q={encoded_email}',
                "desc": "Öffentliche Google Groups und Usenet-Archive."
            },
            {
                "title": "Open-Source & IT Listen (Debian, Ubuntu, Apache)",
                "url": f'https://www.google.com/search?q=(site:lists.debian.org+OR+site:lists.ubuntu.com+OR+site:lists.apache.org)+"{encoded_email}"',
                "desc": "Entwickler- und Supportlisten großer IT- und Open-Source-Ökosysteme."
            },
            {
                "title": "Security & Vulnerability Lists (SecLists, Bugtraq)",
                "url": f'https://www.google.com/search?q=(site:seclists.org+OR+site:lists.openwall.net)+"{encoded_email}"',
                "desc": "Sicherheitsmailinglisten und Offenlegungsarchive."
            }
        ]
    }

    # Live Automated Query against MARC.info (Mailing List ARChives)
    try:
        marc_query_url = f"https://marc.info/?s={clean_email}"
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            resp = await client.get(marc_query_url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})
            if resp.status_code == 200:
                html = resp.text
                # Find occurrences of list links: href="?l=listname&m=..."
                list_matches = re.findall(r'\?l=([a-zA-Z0-9\-_]+)', html)
                if list_matches:
                    unique_lists = list(dict.fromkeys(list_matches))
                    result["found_in_marc"] = True
                    result["marc_hit_count"] = len(list_matches)
                    result["detected_lists"] = unique_lists[:6] # Top 6 lists
    except Exception:
        pass

    return {"success": True, "data": result}
