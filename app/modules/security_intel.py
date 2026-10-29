import re
import httpx
from typing import Dict, Any, List, Optional

async def check_infostealer_malware(email: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """
    Queries Hudson Rock's Cybercrime & Infostealer Intelligence API.
    Identifies whether machines authenticated with this email were infected
    by infostealer trojans (RedLine, Vidar, Racoon, Lumma) leaking credentials.
    """
    if not email or "@" not in email:
        return {"checked": False, "infected": False, "error": "Keine gültige E-Mail-Adresse"}

    email_clean = email.strip().lower()
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email_clean}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    should_close = False
    if client is None:
        client = httpx.AsyncClient(timeout=7.0, follow_redirects=True)
        should_close = True

    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stealers = data.get("stealers", []) or []
            infected = len(stealers) > 0
            
            # Format infected malware families if any
            families = []
            for s in stealers:
                fam = s.get("malware_family") or s.get("stealer_family") or "Infostealer"
                if fam not in families:
                    families.append(fam)

            return {
                "checked": True,
                "infected": infected,
                "stealers_count": len(stealers),
                "families": families,
                "message": data.get("message", ""),
                "corporate_services": data.get("total_corporate_services", 0),
                "user_services": data.get("total_user_services", 0)
            }
        return {"checked": False, "infected": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"checked": False, "infected": False, "error": str(e)}
    finally:
        if should_close:
            await client.aclose()

async def check_pgp_keyserver(email: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """
    Queries the global OpenPGP Keyserver network (keyserver.ubuntu.com)
    for public cryptographic keys associated with this email address.
    """
    if not email or "@" not in email:
        return {"checked": False, "has_pgp": False}

    email_clean = email.strip().lower()
    url = f"https://keyserver.ubuntu.com/pks/lookup?search={email_clean}&op=index&options=mr"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "text/plain"
    }

    should_close = False
    if client is None:
        client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
        should_close = True

    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.split("\n") if l.startswith("pub:")]
            keys = []
            for l in lines:
                parts = l.split(":")
                if len(parts) > 1 and parts[1]:
                    keys.append(parts[1])

            return {
                "checked": True,
                "has_pgp": len(keys) > 0,
                "key_count": len(keys),
                "keys": keys[:3],
                "lookup_url": f"https://keyserver.ubuntu.com/pks/lookup?search={email_clean}&op=vindex"
            }
        elif resp.status_code == 404:
            return {
                "checked": True,
                "has_pgp": False,
                "key_count": 0
            }
        return {"checked": False, "has_pgp": False}
    except Exception as e:
        return {"checked": False, "has_pgp": False, "error": str(e)}
    finally:
        if should_close:
            await client.aclose()
