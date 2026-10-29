import re
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
