import re
import asyncio
import httpx
from typing import AsyncGenerator, Dict, Any, List, Optional

# Verified, reliable platforms with deterministic profile verification
PLATFORMS: List[Dict[str, Any]] = [
    # Developer & Tech
    {"name": "GitHub", "category": "Tech / Dev", "url": "https://github.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "GitLab", "category": "Tech / Dev", "url": "https://gitlab.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "DockerHub", "category": "Tech / Dev", "url": "https://hub.docker.com/v2/users/{}/", "check_type": "status_code", "error_code": 404, "profile_url": "https://hub.docker.com/u/{}"},
    {"name": "Dev.to", "category": "Tech / Dev", "url": "https://dev.to/{}", "check_type": "status_code", "error_code": 404},
    {"name": "HackerNews", "category": "Tech / Dev", "url": "https://news.ycombinator.com/user?id={}", "check_type": "text_not_contains", "error_text": "No such user."},
    {"name": "NPM", "category": "Tech / Dev", "url": "https://www.npmjs.com/~{}", "check_type": "status_code", "error_code": 404},
    {"name": "LeetCode", "category": "Tech / Dev", "url": "https://leetcode.com/u/{}/", "check_type": "status_code", "error_code": 404},
    {"name": "Replit", "category": "Tech / Dev", "url": "https://replit.com/@{}", "check_type": "status_code", "error_code": 404},

    # Social & Community
    {"name": "Reddit", "category": "Social Media", "url": "https://www.reddit.com/user/{}/about.json", "check_type": "status_code", "error_code": 404, "profile_url": "https://www.reddit.com/user/{}"},
    {"name": "Telegram", "category": "Social Media", "url": "https://t.me/{}", "check_type": "text_contains", "match_text": "tgme_page_extra"},
    {"name": "Mastodon.social", "category": "Social Media", "url": "https://mastodon.social/@{}", "check_type": "status_code", "error_code": 404},

    # Video & Media
    {"name": "YouTube", "category": "Video & Media", "url": "https://www.youtube.com/@{}", "check_type": "status_code", "error_code": 404},
    {"name": "Vimeo", "category": "Video & Media", "url": "https://vimeo.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "SoundCloud", "category": "Music & Audio", "url": "https://soundcloud.com/{}", "check_type": "status_code", "error_code": 404},

    # Creative & Portfolios
    {"name": "Behance", "category": "Design & Art", "url": "https://www.behance.net/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Dribbble", "category": "Design & Art", "url": "https://dribbble.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "DeviantArt", "category": "Design & Art", "url": "https://www.deviantart.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Flickr", "category": "Design & Art", "url": "https://www.flickr.com/people/{}", "check_type": "status_code", "error_code": 404},

    # Gaming
    {"name": "Steam", "category": "Gaming", "url": "https://steamcommunity.com/id/{}", "check_type": "text_not_contains", "error_text": "The specified profile could not be found."},
    {"name": "Chess.com", "category": "Gaming", "url": "https://www.chess.com/member/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Lichess", "category": "Gaming", "url": "https://lichess.org/@/{}", "check_type": "status_code", "error_code": 404},

    # Identity, Bio & Funding
    {"name": "Keybase", "category": "Security & Identity", "url": "https://keybase.io/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Gravatar", "category": "Security & Identity", "url": "https://en.gravatar.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Linktree", "category": "Bio Links", "url": "https://linktr.ee/{}", "check_type": "status_code", "error_code": 404},
    {"name": "About.me", "category": "Bio Links", "url": "https://about.me/{}", "check_type": "status_code", "error_code": 404},
    {"name": "BuyMeACoffee", "category": "Funding / Support", "url": "https://www.buymeacoffee.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "Patreon", "category": "Funding / Support", "url": "https://www.patreon.com/{}", "check_type": "status_code", "error_code": 404},
    {"name": "ProductHunt", "category": "Tech / Community", "url": "https://www.producthunt.com/@{}", "check_type": "status_code", "error_code": 404},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,de;q=0.8",
}

# Pre-set consent cookies to prevent EU consent wall redirects (e.g. YouTube consent.youtube.com)
COOKIES = {
    "SOCS": "CAESEwgDEgk2MTQ1Mjg4NDcaAmVuIAEaBgiA_LyaBg",
}

# Substrings in final redirected URL indicating an error, login wall, or 404 fallback
DISALLOWED_REDIRECT_SUBSTRINGS = [
    "/404", "page-not-found", "not-found", "not_found", "error/404",
    "users/sign_in", "login", "/signin", "accounts.google.com",
    "consent.youtube.com", "consent.google.com", "challenge",
]

# Cloudflare, Turnstile, reCAPTCHA, and bot protection markers
WAF_CHALLENGE_SUBSTRINGS = [
    "attention required! | cloudflare",
    "cf_challenge",
    "checking your browser",
    "client challenge",
    "just a moment...",
    "cf-browser-verification",
    "recaptcha",
    "bot detection",
    "please verify you are a human",
]

# Universal soft-404 phrases inside page titles and headers
SOFT_404_HEADER_SUBSTRINGS = [
    "the specified profile could not be found",
    "user not found",
    "page not found",
    "profile not found",
    "this account does not exist",
    "this profile does not exist",
    "no such user",
    "404 not found",
    "404 - page not found",
]

def _extract_page_snippet(html_text: str) -> str:
    """Extracts meta description, title or brief visible text snippet"""
    if not html_text:
        return ""
    # Try meta description
    m = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html_text, re.IGNORECASE)
    if not m:
        m = re.search(r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', html_text, re.IGNORECASE)
    if m:
        snippet = m.group(1).strip()
        if snippet and len(snippet) > 10:
            return snippet[:160] + ("..." if len(snippet) > 160 else "")

    # Try title
    t = re.search(r'<title>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
    if t:
        title = re.sub(r'\s+', ' ', t.group(1)).strip()
        if title:
            return title[:120]

    return ""

def _calculate_match_score(
    text: str,
    full_name: str = "",
    city: str = "",
    employer: str = "",
    keywords: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Correlates profile page text against user-provided context (name, location, employer, keywords).
    Returns score (0-100) and matched attributes.
    """
    text_lower = text.lower()
    matches = []
    score = 0

    has_context = bool(full_name or city or employer or (keywords and len(keywords) > 0))
    if not has_context:
        return {"score": None, "matches": [], "confidence": "no_filter"}

    # 1. Full name match
    if full_name:
        fn_clean = full_name.strip().lower()
        if fn_clean in text_lower:
            score += 45
            matches.append(f"Name: {full_name}")
        else:
            parts = [p for p in fn_clean.split() if len(p) > 2]
            for p in parts:
                if p in text_lower:
                    score += 20
                    matches.append(f"Namensbestandteil: {p.capitalize()}")
                    break

    # 2. City / Location match
    if city:
        city_clean = city.strip().lower()
        if city_clean in text_lower:
            score += 35
            matches.append(f"Ort: {city}")

    # 3. Employer match
    if employer:
        emp_clean = employer.strip().lower()
        if emp_clean in text_lower:
            score += 30
            matches.append(f"Firma: {employer}")

    # 4. Keywords match
    if keywords:
        for kw in keywords:
            kw_clean = kw.strip().lower()
            if kw_clean and kw_clean in text_lower:
                score += 15
                matches.append(f"Keyword: {kw}")

    score = min(score, 100)

    if score >= 70:
        confidence = "high"
    elif score >= 35:
        confidence = "medium"
    elif score > 0:
        confidence = "low"
    else:
        confidence = "unlikely"

    return {
        "score": score,
        "matches": matches,
        "confidence": confidence
    }

async def check_platform(
    client: httpx.AsyncClient,
    platform: Dict[str, Any],
    username: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Multi-stage verification pipeline to completely eliminate false positives:
    1. HTTP Status Code validation (must be 200).
    2. Final Redirect destination check (rejects redirects to login, /404, or site root).
    3. WAF / Bot challenge detection (Cloudflare, reCAPTCHA, Turnstile).
    4. Platform-specific rule validation (text_contains / text_not_contains).
    5. Universal soft-404 headers and title inspection.
    """
    url = platform["url"].format(username)
    profile_url = platform.get("profile_url", url).format(username)
    check_type = platform.get("check_type", "status_code")
    
    result = {
        "platform": platform["name"],
        "category": platform["category"],
        "url": profile_url,
        "exists": False,
        "status": "not_found",
        "snippet": "",
        "match": {"score": None, "matches": [], "confidence": "none"},
        "error": None
    }
    
    try:
        response = await client.get(url, timeout=7.0, follow_redirects=True)
        
        # Stage 1: Status code check
        if response.status_code != 200:
            result["exists"] = False
            result["status"] = "not_found"
            return result

        # Stage 2: Final redirect target check
        final_url_str = str(response.url).lower()
        for bad_sub in DISALLOWED_REDIRECT_SUBSTRINGS:
            if bad_sub in final_url_str:
                result["exists"] = False
                result["status"] = "not_found"
                return result

        # If platform URL expected a profile path but response was redirected to domain root
        if response.url.path in ("", "/") and len(platform["url"].split("/")) > 4:
            result["exists"] = False
            result["status"] = "not_found"
            return result

        body_lower = response.text.lower()

        # Stage 3: Anti-bot / WAF / Cloudflare challenge inspection
        for waf in WAF_CHALLENGE_SUBSTRINGS:
            if waf in body_lower:
                result["exists"] = False
                result["status"] = "not_found"
                return result

        # Stage 4: Platform-specific check rules
        if check_type == "text_not_contains":
            error_text = platform.get("error_text", "").lower()
            if error_text and error_text in body_lower:
                result["exists"] = False
                result["status"] = "not_found"
                return result
                
        elif check_type == "text_contains":
            match_text = platform.get("match_text", "").lower()
            if not match_text or match_text not in body_lower:
                result["exists"] = False
                result["status"] = "not_found"
                return result

        # Stage 5: Universal soft-404 inspection in titles and main headers
        for s404 in SOFT_404_HEADER_SUBSTRINGS:
            if f"<title>{s404}" in body_lower or f"<h1>{s404}" in body_lower or f'"{s404}"' in body_lower:
                result["exists"] = False
                result["status"] = "not_found"
                return result

        # All stages passed: Profile is confirmed found
        result["exists"] = True
        result["status"] = "found"
        result["snippet"] = _extract_page_snippet(response.text)

        if context:
            result["match"] = _calculate_match_score(
                response.text,
                full_name=context.get("name", ""),
                city=context.get("city", ""),
                employer=context.get("employer", ""),
                keywords=context.get("keywords", [])
            )
                
    except (httpx.TimeoutException, httpx.RequestError, Exception):
        result["exists"] = False
        result["status"] = "not_found"
        
    return result


async def scan_username_stream(
    username: str,
    context: Optional[Dict[str, Any]] = None
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Scans platforms concurrently using a Semaphore and yields exclusively confirmed accounts as they appear.
    Platforms where the username does NOT exist are never emitted as profile results.
    If an email address is entered, automatically performs cryptographic Gravatar OSINT resolution to determine
    the associated online handle and cascades the search.
    """
    target_username = username.strip()
    gravatar_hit = None

    if "@" in target_username:
        from app.modules.email_account_checker import lookup_gravatar
        grav = await lookup_gravatar(target_username)
        if grav and grav.get("username"):
            grav_handle = grav["username"]
            target_username = grav_handle
            gravatar_hit = {
                "platform": "Gravatar (E-Mail verknüpft)",
                "category": "E-Mail OSINT",
                "url": grav.get("profile_url") or f"https://gravatar.com/{grav_handle}",
                "exists": True,
                "status": "found",
                "snippet": f"Kryptografisch verknüpfter Account-Handle für {username}: @{grav_handle} (Standort: {grav.get('location') or 'nicht angegeben'})",
                "match": {
                    "score": 100,
                    "matches": [f"E-Mail-Hash aufgelöst zu @{grav_handle}"],
                    "confidence": "high"
                }
            }
        else:
            target_username = target_username.split("@")[0].strip()

    total = len(PLATFORMS)
    checked = 0
    found_count = 0
    high_match_count = 0

    if gravatar_hit:
        found_count += 1
        high_match_count += 1
        gravatar_hit["progress"] = {
            "found": found_count,
            "high_match_count": high_match_count,
            "percent": 5.0
        }
        yield gravatar_hit
    
    sem = asyncio.Semaphore(12)
    
    async with httpx.AsyncClient(headers=HEADERS, cookies=COOKIES, timeout=8.0, follow_redirects=True) as client:
        async def sem_check(p):
            async with sem:
                return await check_platform(client, p, target_username, context=context)
        
        tasks = [asyncio.create_task(sem_check(p)) for p in PLATFORMS]
        
        for future in asyncio.as_completed(tasks):
            res = await future
            checked += 1
            if res.get("exists") is True:
                found_count += 1
                if res.get("match", {}).get("confidence") in ["high", "medium"]:
                    high_match_count += 1
            
                res["progress"] = {
                    "found": found_count,
                    "high_match_count": high_match_count,
                    "percent": round((checked / total) * 100, 1)
                }
                yield res
            else:
                # Emit progress ping only, never the un-found platform
                yield {
                    "event": "progress",
                    "progress": {
                        "found": found_count,
                        "high_match_count": high_match_count,
                        "percent": round((checked / total) * 100, 1)
                    }
                }

async def scan_usernames_fast(
    username: str,
    context: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Scans all platforms concurrently and returns exclusively verified found accounts.
    Platforms that return 404/not_found or errors are completely excluded.
    If an email is passed, resolves it to the underlying handle automatically via Gravatar.
    """
    target_username = username.strip()
    additional_profiles = []

    if "@" in target_username:
        from app.modules.email_account_checker import lookup_gravatar
        grav = await lookup_gravatar(target_username)
        if grav and grav.get("username"):
            grav_handle = grav["username"]
            target_username = grav_handle
            additional_profiles.append({
                "platform": "Gravatar (E-Mail verknüpft)",
                "category": "E-Mail OSINT",
                "url": grav.get("profile_url") or f"https://gravatar.com/{grav_handle}",
                "exists": True,
                "status": "found",
                "snippet": f"Kryptografisch verknüpfter Account-Handle für {username}: @{grav_handle} (Standort: {grav.get('location') or 'nicht angegeben'})",
                "match": {
                    "score": 100,
                    "matches": [f"E-Mail-Hash aufgelöst zu @{grav_handle}"],
                    "confidence": "high"
                }
            })
        else:
            target_username = target_username.split("@")[0].strip()

    sem = asyncio.Semaphore(15)
    async with httpx.AsyncClient(headers=HEADERS, cookies=COOKIES, timeout=7.0, follow_redirects=True) as client:
        async def sem_check(p):
            async with sem:
                return await check_platform(client, p, target_username, context=context)
        
        tasks = [asyncio.create_task(sem_check(p)) for p in PLATFORMS]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        verified = [r for r in results if isinstance(r, dict) and r.get("exists") is True]
        
        # Merge Gravatar hit if not already in verified
        seen_urls = {p.get("url") for p in verified}
        for add_p in additional_profiles:
            if add_p.get("url") not in seen_urls:
                verified.insert(0, add_p)
                
        return verified

