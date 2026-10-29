import urllib.parse
from typing import Dict, Any, List, Optional

def canonical_image_key(url: str) -> str:
    """Normalizes an image URL so duplicates across sizes, subdomains, and CDN mirrors share a key."""
    if not url:
        return ""
    clean = url.strip()
    
    # Gravatar normalization (e.g. 0.gravatar.com, secure.gravatar.com, ?s=400)
    if "gravatar.com/avatar/" in clean:
        parts = clean.split("gravatar.com/avatar/")[1].split("?")[0].split("/")[0]
        return f"gravatar:{parts.lower()}"
        
    # GitHub avatar normalization
    if "avatars.githubusercontent.com/u/" in clean:
        u_id = clean.split("avatars.githubusercontent.com/u/")[1].split("?")[0]
        return f"github_u:{u_id}"
    if "github.com/" in clean and clean.endswith(".png"):
        gh_user = clean.split("github.com/")[1].replace(".png", "").strip().lower()
        return f"github_user:{gh_user}"

    # Google avatar normalization
    if "googleusercontent.com" in clean:
        base = clean.split("=")[0]
        return f"google:{base}"

    # Generic: strip query parameters and lowercase
    base = clean.split("?")[0].rstrip("/").lower()
    return base

def collect_discovered_images(
    email_recon_res: Optional[Dict[str, Any]] = None,
    found_profiles: Optional[List[Dict[str, Any]]] = None,
    session_avatar: Optional[str] = None,
    email: Optional[str] = None,
    username: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Aggregates all profile pictures, avatars, and photos discovered during OSINT reconnaissance.
    Groups identical images together, calculates occurrence counts (for word-cloud sizing),
    and records all source platform links.
    """
    candidates = []

    # 1. Collect from Email Account Recon (Gravatar, Duolingo, GitHub)
    if email_recon_res:
        # Gravatar main avatar
        if email_recon_res.get("avatar_url"):
            candidates.append({
                "url": email_recon_res["avatar_url"],
                "platform": "Gravatar / Automattic",
                "source_url": f"https://en.gravatar.com/{username}" if username else "https://gravatar.com",
                "title": "Verifiziertes Gravatar-Profil"
            })

        # Gravatar additional gallery photos
        for acc in email_recon_res.get("registered_accounts", []):
            photos = acc.get("photos", [])
            for p_url in photos:
                if p_url:
                    candidates.append({
                        "url": p_url,
                        "platform": "Gravatar Fotogalerie",
                        "source_url": acc.get("profile_url") or "https://gravatar.com",
                        "title": "Gravatar Galerie-Foto"
                    })
            if acc.get("service") == "Duolingo" and acc.get("avatar_url"):
                candidates.append({
                    "url": acc["avatar_url"],
                    "platform": "Duolingo",
                    "source_url": acc.get("profile_url") or "https://www.duolingo.com",
                    "title": "Duolingo Lernprofil"
                })
            elif acc.get("service") == "GitHub" and acc.get("avatar_url"):
                candidates.append({
                    "url": acc["avatar_url"],
                    "platform": "GitHub",
                    "source_url": acc.get("profile_url") or "https://github.com",
                    "title": "GitHub Commit-Autor"
                })

    # 2. Collect from Verified Discovered Profiles
    if found_profiles:
        for p in found_profiles:
            if not p.get("exists"):
                continue
            p_name = p.get("platform", "")
            p_url = p.get("url", "")

            # If profile already provides an explicit avatar_url
            if p.get("avatar_url"):
                candidates.append({
                    "url": p["avatar_url"],
                    "platform": p_name,
                    "source_url": p_url,
                    "title": f"Profil auf {p_name}"
                })

            # Check known platform avatar endpoints
            if "GitHub" in p_name and ("github.com/" in p_url):
                gh_user = p_url.rstrip("/").split("/")[-1]
                if gh_user:
                    candidates.append({
                        "url": f"https://github.com/{gh_user}.png?size=400",
                        "platform": "GitHub",
                        "source_url": p_url,
                        "title": f"GitHub Profilbild (@{gh_user})"
                    })
            elif "GitLab" in p_name and ("gitlab.com/" in p_url):
                gl_user = p_url.rstrip("/").split("/")[-1]
                if gl_user:
                    candidates.append({
                        "url": f"https://gitlab.com/{gl_user}.png",
                        "platform": "GitLab",
                        "source_url": p_url,
                        "title": f"GitLab Profilbild (@{gl_user})"
                    })
            elif "Keybase" in p_name and ("keybase.io/" in p_url):
                kb_user = p_url.rstrip("/").split("/")[-1]
                if kb_user:
                    candidates.append({
                        "url": f"https://keybase.io/{kb_user}/picture",
                        "platform": "Keybase",
                        "source_url": p_url,
                        "title": f"Keybase Identität (@{kb_user})"
                    })

    # 3. Collect from Current Session / OAuth Avatar (Google / GitHub)
    if session_avatar:
        provider = "Google" if "google" in session_avatar else "OAuth-Konto"
        candidates.append({
            "url": session_avatar,
            "platform": f"{provider} (Verifiziert)",
            "source_url": session_avatar,
            "title": f"Aktives {provider}-Profilbild"
        })

    # Group candidates by canonical key
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in candidates:
        url = item.get("url", "").strip()
        if not url:
            continue
        key = canonical_image_key(url)
        if not key:
            continue

        if key not in grouped:
            grouped[key] = {
                "id": key,
                "url": url,
                "count": 0,
                "sources": []
            }

        # Check if this exact source URL is already attached
        existing_source_urls = {s.get("source_url") for s in grouped[key]["sources"]}
        if item["source_url"] not in existing_source_urls:
            grouped[key]["sources"].append({
                "platform": item["platform"],
                "url": item["source_url"],
                "title": item["title"]
            })
            grouped[key]["count"] += 1

    # Format result list sorted by occurrence count descending
    result = list(grouped.values())
    result.sort(key=lambda x: x["count"], reverse=True)

    # Assign size tiers and Reverse-Image search queries
    for idx, img in enumerate(result):
        cnt = img["count"]
        if cnt >= 3:
            img["size_tier"] = "xl"      # Hero / large
            img["weight_label"] = f"Häufig gefunden ({cnt} Quellen)"
        elif cnt == 2:
            img["size_tier"] = "lg"      # Medium-large
            img["weight_label"] = f"Mehrfach gefunden ({cnt} Quellen)"
        else:
            img["size_tier"] = "md"      # Compact single
            img["weight_label"] = "Einzelfund"

        quoted_url = urllib.parse.quote(img["url"], safe="")
        img["google_lens_url"] = f"https://lens.google.com/uploadbyurl?url={quoted_url}"
        img["tineye_url"] = f"https://tineye.com/search?url={quoted_url}"
        img["yandex_url"] = f"https://yandex.com/images/search?rpt=imageview&url={quoted_url}"

    return result
