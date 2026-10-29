import hashlib
import asyncio
import httpx
from typing import Dict, Any, List, Optional

async def lookup_gravatar(email: str, client: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, Any]]:
    """
    Cryptographically queries Gravatar's public OSINT API via email MD5 hash.
    Reveals confirmed public handles, full names, photos, and locations linked to this email.
    """
    if not email or "@" not in email:
        return None
        
    email_clean = email.strip().lower()
    email_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
    url = f"https://en.gravatar.com/{email_hash}.json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    should_close = False
    if client is None:
        client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
        should_close = True

    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entry", [])
            if entries:
                entry = entries[0]
                username = entry.get("preferredUsername")
                display_name = entry.get("displayName")
                location = entry.get("currentLocation")
                profile_url = entry.get("profileUrl") or f"https://gravatar.com/{username}" if username else None
                avatar_url = entry.get("thumbnailUrl")
                about = entry.get("aboutMe")

                # Parse photos gallery
                photos = []
                for p in entry.get("photos", []) or []:
                    if isinstance(p, dict) and p.get("value"):
                        photos.append(p["value"])
                if avatar_url and avatar_url not in photos:
                    photos.insert(0, avatar_url)

                # Parse linked external accounts if disclosed
                linked_accounts = []
                for acc in entry.get("accounts", []) or []:
                    if isinstance(acc, dict) and acc.get("shortname"):
                        linked_accounts.append({
                            "platform": acc.get("shortname"),
                            "url": acc.get("url"),
                            "username": acc.get("username")
                        })

                return {
                    "service": "Gravatar / Automattic",
                    "category": "Identity & Profile",
                    "status": "Aktiv registriert",
                    "exists": True,
                    "username": username,
                    "display_name": display_name,
                    "location": location,
                    "profile_url": profile_url,
                    "avatar_url": avatar_url,
                    "photos": photos,
                    "about": about,
                    "linked_accounts": linked_accounts,
                    "evidence": f"Kryptografisch verifizierter MD5-Hash ({email_hash[:8]}...)"
                }
        return None
    except Exception:
        return None
    finally:
        if should_close:
            await client.aclose()

async def lookup_duolingo(email: str, client: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, Any]]:
    """
    Checks if the email is registered on Duolingo via their public account verification endpoint.
    """
    if not email or "@" not in email:
        return None

    email_clean = email.strip().lower()
    url = f"https://www.duolingo.com/2017-06-30/users?email={email_clean}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    should_close = False
    if client is None:
        client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
        should_close = True

    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            users = data.get("users", [])
            if users:
                user = users[0]
                has_apple = user.get("hasAppleId", False)
                has_google = user.get("hasGoogleId", False)
                has_facebook = user.get("hasFacebookId", False)
                
                auth_methods = []
                if has_apple: auth_methods.append("Apple ID")
                if has_google: auth_methods.append("Google")
                if has_facebook: auth_methods.append("Facebook")
                auth_str = f" via {', '.join(auth_methods)}" if auth_methods else ""

                username = user.get("username") or ""
                profile_url = f"https://www.duolingo.com/profile/{username}" if username else "https://www.duolingo.com"
                
                # Extract Duolingo avatar picture
                duo_picture = user.get("picture")
                if duo_picture and isinstance(duo_picture, str):
                    if duo_picture.startswith("//"):
                        duo_picture = "https:" + duo_picture

                return {
                    "service": "Duolingo",
                    "category": "Bildung & Sprachen",
                    "status": "Aktiv registriert",
                    "exists": True,
                    "username": username if username else None,
                    "profile_url": profile_url,
                    "avatar_url": duo_picture,
                    "evidence": f"Aktiver Account bestätigt{auth_str}"
                }
        return None
    except Exception:
        return None
    finally:
        if should_close:
            await client.aclose()

async def lookup_github_email(email: str, client: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, Any]]:
    """
    Checks if the email has public commits or is associated with a public GitHub account.
    """
    if not email or "@" not in email:
        return None

    email_clean = email.strip().lower()
    url = f"https://api.github.com/search/commits?q=author-email:{email_clean}"
    headers = {
        "User-Agent": "Selfscanner-OSINT/1.0",
        "Accept": "application/vnd.github.cloak-preview"
    }

    should_close = False
    if client is None:
        client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
        should_close = True

    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total > 0:
                items = data.get("items", [])
                author_login = None
                avatar_url = None
                if items:
                    first = items[0]
                    author_obj = first.get("author") or {}
                    author_login = author_obj.get("login")
                    avatar_url = author_obj.get("avatar_url")
                if not avatar_url and author_login:
                    avatar_url = f"https://github.com/{author_login}.png"

                return {
                    "service": "GitHub",
                    "category": "Tech / Open Source",
                    "status": "Öffentliche Commits",
                    "exists": True,
                    "username": author_login,
                    "profile_url": f"https://github.com/{author_login}" if author_login else f"https://github.com/search?q=author-email:{email_clean}&type=commits",
                    "avatar_url": avatar_url,
                    "evidence": f"{total} öffentliche Git-Commits gefunden"
                }
        return None
    except Exception:
        return None
    finally:
        if should_close:
            await client.aclose()

async def check_email_accounts(email: str) -> Dict[str, Any]:
    """
    Orchestrates email-based account discovery across supported platforms.
    Extracts associated usernames, names, locations, and confirmed active registrations.
    """
    if not email or "@" not in email:
        return {
            "success": False,
            "error": "Ungültige E-Mail-Adresse",
            "registered_accounts": [],
            "discovered_usernames": []
        }

    async with httpx.AsyncClient(timeout=7.0, follow_redirects=True) as client:
        gravatar_task = lookup_gravatar(email, client)
        duolingo_task = lookup_duolingo(email, client)
        github_task = lookup_github_email(email, client)

        gravatar_res, duolingo_res, github_res = await asyncio.gather(
            gravatar_task, duolingo_task, github_task, return_exceptions=True
        )

    registered_accounts = []
    discovered_usernames = []
    discovered_location = None
    discovered_name = None
    avatar_url = None

    if isinstance(gravatar_res, dict) and gravatar_res:
        registered_accounts.append(gravatar_res)
        if gravatar_res.get("username"):
            discovered_usernames.append(gravatar_res["username"])
        if gravatar_res.get("location"):
            discovered_location = gravatar_res["location"]
        if gravatar_res.get("display_name"):
            discovered_name = gravatar_res["display_name"]
        if gravatar_res.get("avatar_url"):
            avatar_url = gravatar_res["avatar_url"]

    if isinstance(duolingo_res, dict) and duolingo_res:
        registered_accounts.append(duolingo_res)
        if duolingo_res.get("username") and duolingo_res["username"] not in discovered_usernames:
            discovered_usernames.append(duolingo_res["username"])

    if isinstance(github_res, dict) and github_res:
        registered_accounts.append(github_res)
        if github_res.get("username") and github_res["username"] not in discovered_usernames:
            discovered_usernames.append(github_res["username"])

    # Local-part fallback candidate
    local_part = email.split("@")[0].strip()
    # Filter out generic terms
    if local_part and local_part.lower() not in ["info", "contact", "kontakt", "mail", "admin", "office", "support"]:
        if local_part not in discovered_usernames:
            discovered_usernames.append(local_part)

    return {
        "success": True,
        "email": email,
        "registered_accounts": registered_accounts,
        "discovered_usernames": discovered_usernames,
        "discovered_location": discovered_location,
        "discovered_name": discovered_name,
        "avatar_url": avatar_url,
        "total_found": len(registered_accounts)
    }
