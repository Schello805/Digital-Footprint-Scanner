import re
import asyncio
from typing import Dict, Any, List
import dns.resolver

def clean_domain(domain_input: str) -> str:
    domain = domain_input.strip().lower()
    # Remove protocol
    domain = re.sub(r"^https?://", "", domain)
    # Remove path / query
    domain = domain.split("/")[0]
    # Remove port
    domain = domain.split(":")[0]
    return domain

def check_domain_dns(domain_input: str) -> Dict[str, Any]:
    domain = clean_domain(domain_input)
    if not domain or "." not in domain:
        return {"success": False, "error": "Bitte einen gültigen Domainnamen eingeben (z. B. beispiel.de)"}

    # SSRF & Private Network Protection
    from app.modules.security import is_ssrf_dangerous
    if is_ssrf_dangerous(domain):
        return {"success": False, "error": "Sicherheitswarnung: Private, lokale oder reservierte Netzadressen können nicht gescannt werden."}

    result = {
        "domain": domain,
        "records": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": None
        },
        "email_security": {
            "spf": {"found": False, "raw": None, "policy": None, "status": "missing", "assessment": "Kein SPF-Eintrag gefunden (Jeder kann E-Mails in deinem Namen fälschen)"},
            "dmarc": {"found": False, "raw": None, "policy": None, "status": "missing", "assessment": "Kein DMARC-Eintrag gefunden (Kein Schutz vor Mail-Spoofing)"}
        },
        "identified_providers": [],
        "risk_level": "LOW",
        "warnings": []
    }

    try:
        resolver = dns.resolver.Resolver()
    except Exception:
        # Fallback to public resolvers (Cloudflare / Google) if /etc/resolv.conf cannot be read
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    # A Records
    try:
        answers = resolver.resolve(domain, "A")
        result["records"]["A"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # AAAA Records
    try:
        answers = resolver.resolve(domain, "AAAA")
        result["records"]["AAAA"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # NS Records
    try:
        answers = resolver.resolve(domain, "NS")
        result["records"]["NS"] = [r.to_text().rstrip(".") for r in answers]
        for ns in result["records"]["NS"]:
            ns_lower = ns.lower()
            if "cloudflare" in ns_lower:
                result["identified_providers"].append("Cloudflare CDN / DNS")
            elif "awsdns" in ns_lower:
                result["identified_providers"].append("AWS Route 53")
            elif "googledomains" in ns_lower or "google" in ns_lower:
                result["identified_providers"].append("Google Cloud DNS")
            elif "hetzner" in ns_lower:
                result["identified_providers"].append("Hetzner DNS")
    except Exception:
        pass

    # MX Records
    try:
        answers = resolver.resolve(domain, "MX")
        mx_list = []
        for r in answers:
            host = r.exchange.to_text().rstrip(".")
            mx_list.append({"priority": r.preference, "host": host})
            host_lower = host.lower()
            if "google" in host_lower or "googlemail" in host_lower:
                result["identified_providers"].append("Google Workspace / Gmail")
            elif "outlook" in host_lower or "microsoft" in host_lower:
                result["identified_providers"].append("Microsoft 365 / Outlook")
            elif "protonmail" in host_lower:
                result["identified_providers"].append("ProtonMail (Verschlüsselt)")
        result["records"]["MX"] = sorted(mx_list, key=lambda x: x["priority"])
    except Exception:
        pass

    # TXT Records & SPF Check
    try:
        answers = resolver.resolve(domain, "TXT")
        txt_records = []
        for r in answers:
            # Join multiple character strings in TXT record
            txt_content = "".join([part.decode("utf-8", errors="replace") for part in r.strings])
            txt_records.append(txt_content)
            
            if txt_content.startswith("v=spf1"):
                result["email_security"]["spf"]["found"] = True
                result["email_security"]["spf"]["raw"] = txt_content
                if "-all" in txt_content:
                    result["email_security"]["spf"]["policy"] = "Strict (-all)"
                    result["email_security"]["spf"]["status"] = "secure"
                    result["email_security"]["spf"]["assessment"] = "Strikter SPF-Schutz (-all): Nicht autorisierte Server werden abgewiesen."
                elif "~all" in txt_content:
                    result["email_security"]["spf"]["policy"] = "Softfail (~all)"
                    result["email_security"]["spf"]["status"] = "warning"
                    result["email_security"]["spf"]["assessment"] = "Softfail (~all): Mails werden meist zugestellt, aber als verdächtig markiert."
                elif "+all" in txt_content or "?all" in txt_content:
                    result["email_security"]["spf"]["policy"] = "Neutral/Offen"
                    result["email_security"]["spf"]["status"] = "vulnerable"
                    result["email_security"]["spf"]["assessment"] = "Unsicher (+all/?all): Praktisch jeder Server darf Mails im Namen dieser Domain versenden."

        result["records"]["TXT"] = txt_records
    except Exception:
        pass

    # DMARC Check (_dmarc.<domain>)
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt_content = "".join([part.decode("utf-8", errors="replace") for part in r.strings])
            if txt_content.startswith("v=DMARC1"):
                result["email_security"]["dmarc"]["found"] = True
                result["email_security"]["dmarc"]["raw"] = txt_content
                
                # Check policy
                policy_match = re.search(r"p=([a-zA-Z]+)", txt_content)
                policy = policy_match.group(1).lower() if policy_match else "unknown"
                result["email_security"]["dmarc"]["policy"] = policy
                
                if policy == "reject":
                    result["email_security"]["dmarc"]["status"] = "secure"
                    result["email_security"]["dmarc"]["assessment"] = "Optimal (p=reject): Gefälschte E-Mails werden vom Empfänger-Mailserver sofort verworfen."
                elif policy == "quarantine":
                    result["email_security"]["dmarc"]["status"] = "warning"
                    result["email_security"]["dmarc"]["assessment"] = "Moderat (p=quarantine): Gefälschte E-Mails landen im Spam-Ordner."
                elif policy == "none":
                    result["email_security"]["dmarc"]["status"] = "warning"
                    result["email_security"]["dmarc"]["assessment"] = "Nur Monitoring (p=none): Gefälschte E-Mails werden weiterhin zugestellt!"
    except Exception:
        pass

    # Deduplicate identified providers
    result["identified_providers"] = list(set(result["identified_providers"]))

    # Overall Risk Score
    if result["email_security"]["spf"]["status"] in ["missing", "vulnerable"]:
        result["warnings"].append("Fehlender oder unsicherer SPF-Eintrag – Erhöhte Gefahr für Phishing und Identitätsdiebstahl.")
        result["risk_level"] = "HIGH"

    if result["email_security"]["dmarc"]["status"] in ["missing", "warning"]:
        result["warnings"].append("DMARC ist nicht strikt konfiguriert (reject fehlt).")
        if result["risk_level"] == "LOW":
            result["risk_level"] = "MEDIUM"

    return {"success": True, "data": result}


def parse_domain_target(target: str) -> Dict[str, str]:
    """Parses a domain or URL string into host, apex domain and optional exact URL."""
    raw = target.strip()
    exact_url = ""
    if raw.startswith("http://") or raw.startswith("https://"):
        exact_url = raw
        from urllib.parse import urlparse
        parsed = urlparse(raw)
        host = (parsed.netloc or parsed.path).split(":")[0].lower()
    else:
        host = raw.split("/")[0].split(":")[0].lower()
    
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return {
        "raw": raw,
        "host": host,
        "apex": apex,
        "exact_url": exact_url
    }


async def probe_personal_websites(domain_or_url: str, first_name: str = "", last_name: str = "", username: str = "") -> List[Dict[str, Any]]:
    """
    Intelligently probes for personal websites, landing pages (/ueber-mich/, /about/)
    and subdomains (e.g. michael.schellenberger.biz) under the user's domain.
    """
    import httpx
    from urllib.parse import urlparse
    from app.modules.security import is_ssrf_dangerous

    parsed_info = parse_domain_target(domain_or_url)
    host = parsed_info["host"]
    apex = parsed_info["apex"]
    exact_url = parsed_info["exact_url"]

    if not host or "." not in host or is_ssrf_dangerous(host):
        return []

    candidates = []
    # If the user supplied an explicit URL (e.g. https://michael.schellenberger.biz/ueber-mich/)
    if exact_url:
        candidates.append(exact_url)

    # First name subdomains & personal landing pages
    if first_name:
        fn = first_name.lower().strip()
        candidates.append(f"https://{fn}.{apex}/ueber-mich/")
        candidates.append(f"https://{fn}.{apex}/about/")
        candidates.append(f"https://{fn}.{apex}")
        candidates.append(f"http://{fn}.{apex}")

    if username:
        un = username.lower().strip()
        candidates.append(f"https://{un}.{apex}")

    if host != apex:
        candidates.append(f"https://{host}/ueber-mich/")
        candidates.append(f"https://{host}")

    candidates.append(f"https://{apex}/ueber-mich/")
    candidates.append(f"https://{apex}")
    candidates.append(f"https://www.{apex}")

    # Deduplicate preserving order
    seen = set()
    deduped = []
    for u in candidates:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    found_sites = []
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }) as client:
        for u in deduped:
            try:
                r = await client.get(u)
                if r.status_code == 200:
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    title = re.sub(r"\s+", " ", m.group(1).strip()) if m else "Persönliche Website"
                    final_url = str(r.url)
                    target_host = urlparse(final_url).netloc
                    
                    # Avoid duplicate listing of same URL
                    if any(s["url"] == final_url for s in found_sites):
                        continue

                    found_sites.append({
                        "url": final_url,
                        "title": title,
                        "status": r.status_code,
                        "host": target_host,
                        "domain": apex,
                        "is_personal": any(k in final_url.lower() or k in title.lower() for k in [
                            first_name.lower() if first_name else "",
                            "über mich", "ueber-mich", "about", "digitalcoach", "portfolio", "vita", "resume"
                        ])
                    })
                    # If high-confidence personal about/profile page found, stop probing further paths
                    if "/ueber-mich/" in final_url or "/about/" in final_url:
                        break
            except Exception:
                pass

    return found_sites


async def discover_infrastructure_and_projects(domain_or_url: str) -> Dict[str, Any]:
    """
    Performs passive reverse-IP and server infrastructure reconnaissance
    to discover all co-hosted domains, web projects and subdomains on the same host/server.
    """
    import socket
    import httpx
    from app.modules.security import is_ssrf_dangerous

    parsed_info = parse_domain_target(domain_or_url)
    host = parsed_info["host"]
    apex = parsed_info["apex"]

    if not host or "." not in host or is_ssrf_dangerous(host):
        return {"checked": False, "reason": "Invalid or dangerous host"}

    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"checked": False, "error": f"DNS resolution failed: {str(e)}"}

    if is_ssrf_dangerous(ip):
        return {"checked": False, "reason": "Target resolves to private network"}

    # Skip generic shared CDN IP prefixes (Cloudflare, AWS, etc.) where reverse IP returns millions of random sites
    shared_cdn_prefixes = (
        "104.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "185.199.", "199.232.", "151.101.", "76.76.21.", "216.239."
    )
    if any(ip.startswith(p) for p in shared_cdn_prefixes):
        return {
            "checked": True,
            "server_ip": ip,
            "is_shared_cdn": True,
            "cohosted_domains": [],
            "subdomains": []
        }

    # Query HackerTarget Reverse IP API
    lines = []
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
            if r.status_code == 200 and "error" not in r.text.lower() and "no records" not in r.text.lower():
                lines = [l.strip() for l in r.text.splitlines() if l.strip()]
    except Exception:
        pass

    ignored_suffixes = ("myfritz.net", "vodafone-ip.de", "telekom.de", "1und1.de", "strato.de", "amazonaws.com")
    apex_set = set()
    subdomain_list = []

    for l in lines:
        parts = l.lower().split(".")
        if len(parts) >= 2:
            entry_apex = ".".join(parts[-2:])
            if not any(ign in entry_apex for ign in ignored_suffixes):
                apex_set.add(entry_apex)
                if entry_apex == apex and l.lower() != apex:
                    subdomain_list.append(l.lower())

    # Probe live status and title for all discovered apex domains concurrently
    async def check_domain_status(client, d):
        for proto in ["https://", "http://"]:
            try:
                res = await client.get(f"{proto}{d}", timeout=3.5)
                m = re.search(r"<title[^>]*>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
                title = re.sub(r"\s+", " ", m.group(1).strip()) if m else "Live Webprojekt"
                return {
                    "domain": d,
                    "url": f"{proto}{d}",
                    "status": res.status_code,
                    "title": title[:80],
                    "online": res.status_code < 400
                }
            except Exception:
                continue
        return {
            "domain": d,
            "url": f"https://{d}",
            "status": 0,
            "title": "Nicht erreichbar / Offline",
            "online": False
        }

    cohosted_results = []
    if apex_set:
        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True, verify=False, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT Audit"
        }) as client:
            tasks = [check_domain_status(client, d) for d in sorted(apex_set)]
            cohosted_results = await asyncio.gather(*tasks)

    # Sort cohosted domains: online first, then alphabetical
    cohosted_results.sort(key=lambda x: (not x["online"], x["domain"]))

    return {
        "checked": True,
        "server_ip": ip,
        "is_shared_cdn": False,
        "total_hosts": len(lines),
        "cohosted_domains": cohosted_results,
        "subdomains": sorted(list(set(subdomain_list)))[:25]
    }

