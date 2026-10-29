import hashlib
import re
import httpx
from typing import Dict, Any, List

async def check_password_pwned(password: str) -> Dict[str, Any]:
    """
    Checks if a password has been compromised using the official HIBP k-Anonymity API.
    The password is NEVER transmitted over the network in plaintext or as a full hash.
    Only the first 5 characters of the SHA-1 hash are queried.
    """
    if not password:
        return {"success": False, "error": "Bitte ein Passwort zur Überprüfung eingeben."}

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "Selfscanner-App/1.0",
        "Add-Padding": "true"
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"HIBP API Fehler (Status {resp.status_code})"
                }

            lines = resp.text.splitlines()
            count = 0
            found = False
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    h_suffix, h_count = parts[0].strip(), parts[1].strip()
                    if h_suffix == suffix:
                        count = int(h_count)
                        found = True
                        break

            return {
                "success": True,
                "data": {
                    "pwned": found,
                    "count": count,
                    "sha1_prefix": prefix,
                    "risk_assessment": (
                        f"KRITISCH: Dieses Passwort wurde in {count:,} bekannten Datenlecks gefunden! Verwende es niemals wieder."
                        if found else
                        "SICHER: Dieses Passwort wurde in keinem bekannten HIBP-Datenleak gefunden."
                    )
                }
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Verbindungsfehler zur Breach-API: {str(e)}"
        }

async def check_email_breach(email: str, api_key: str = "") -> Dict[str, Any]:
    """
    Checks an email address for known data breaches.
    1. If an official HIBP API key is present, calls the HIBP v3 API.
    2. If no key is present, automatically queries the free XposedOrNot OSINT Breach API,
       providing immediate breach results without requiring a paid subscription!
    """
    email = email.strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"success": False, "error": "Bitte eine gültige E-Mail-Adresse eingeben."}

    # Method 1: Official HIBP API Key (v3)
    if api_key:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Selfscanner-App/1.0"
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    breaches = resp.json()
                    breach_names = [b.get("Title", b.get("Name", "Unbekannt")) for b in breaches]
                    return {
                        "success": True,
                        "data": {
                            "email": email,
                            "source": "HaveIBeenPwned API (v3)",
                            "has_key": True,
                            "breached": True,
                            "breach_count": len(breaches),
                            "breach_names": breach_names,
                            "breaches": breaches
                        }
                    }
                elif resp.status_code == 404:
                    return {
                        "success": True,
                        "data": {
                            "email": email,
                            "source": "HaveIBeenPwned API (v3)",
                            "has_key": True,
                            "breached": False,
                            "breach_count": 0,
                            "breach_names": [],
                            "breaches": []
                        }
                    }
        except Exception:
            pass # Fallback to XposedOrNot

    # Method 2: Automatic Free OSINT Breach API (XposedOrNot) - No API Key required!
    xon_url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        async with httpx.AsyncClient(timeout=7.0) as client:
            resp = await client.get(xon_url, headers={"User-Agent": "Selfscanner-OSINT-Auditor/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                raw_breaches = data.get("breaches", [])
                # XON often returns [["Breach1", "Breach2", ...]]
                breach_list: List[str] = []
                if raw_breaches and isinstance(raw_breaches[0], list):
                    breach_list = raw_breaches[0]
                elif isinstance(raw_breaches, list):
                    breach_list = [str(b) for b in raw_breaches]

                return {
                    "success": True,
                    "data": {
                        "email": email,
                        "source": "XposedOrNot OSINT Engine (Automatisch & Kostenlos)",
                        "has_key": bool(api_key),
                        "breached": len(breach_list) > 0,
                        "breach_count": len(breach_list),
                        "breach_names": breach_list,
                        "breaches": [{"Title": b, "BreachDate": "Bekannter Vorfall"} for b in breach_list]
                    }
                }
            elif resp.status_code == 404 or "not found" in resp.text.lower():
                return {
                    "success": True,
                    "data": {
                        "email": email,
                        "source": "XposedOrNot OSINT Engine (Automatisch & Kostenlos)",
                        "has_key": bool(api_key),
                        "breached": False,
                        "breach_count": 0,
                        "breach_names": [],
                        "breaches": []
                    }
                }
    except Exception:
        pass

    # Method 3: Fallback intelligence guidance
    return {
        "success": True,
        "data": {
            "email": email,
            "source": "Offizielle OSINT Verifikationsportale",
            "has_key": False,
            "breached": False,
            "breach_count": 0,
            "breach_names": [],
            "message": "Direkte Portal-Links zur manuellen Überprüfung:",
            "direct_links": [
                {
                    "title": "Have I Been Pwned",
                    "url": f"https://haveibeenpwned.com/account/{email}"
                },
                {
                    "title": "HPI Identity Leak Checker",
                    "url": "https://sec.hpi.de/ilc/"
                }
            ]
        }
    }
