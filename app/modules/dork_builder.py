import urllib.parse
from typing import Dict, Any, List

def generate_dorks(name: str = "", city: str = "", company: str = "", username: str = "", email: str = "") -> List[Dict[str, Any]]:
    dorks = []
    
    clean_name = name.strip()
    clean_city = city.strip()
    clean_company = company.strip()
    clean_username = username.strip()
    clean_email = email.strip()

    # Category 1: Person & Wohnort
    if clean_name:
        queries_cat1 = []
        if clean_city:
            q = f'"{clean_name}" "{clean_city}"'
            queries_cat1.append({"title": "Name + Wohnort", "query": q, "desc": "Findet Zeitungsberichte, Vereinsaktivitäten oder lokale Erwähnungen."})
        
        q2 = f'"{clean_name}" ("Telefon" OR "Handy" OR "Adresse" OR "Wohnhaft")'
        queries_cat1.append({"title": "Telefon & Adressspuren", "query": q2, "desc": "Sucht nach unbeabsichtigter Veröffentlichung persönlicher Kontaktdaten."})

        if clean_company:
            q3 = f'"{clean_name}" "{clean_company}"'
            queries_cat1.append({"title": "Name + Arbeitgeber / Firma", "query": q3, "desc": "Mitarbeiterlisten, Organigramme, Pressemitteilungen."})

        dorks.append({
            "category": "👤 Personen- & Kontaktdaten",
            "items": queries_cat1
        })

    # Category 2: Öffentliche Register & Wirtschaft
    if clean_name:
        queries_cat2 = [
            {
                "title": "North Data & Handelsregister",
                "query": f'site:northdata.de "{clean_name}"',
                "desc": "Prüft auf Gesellschafteranteile, Geschäftsführungen oder Prokura in Deutschland/Europa."
            },
            {
                "title": "Offizielles Unternehmensregister",
                "query": f'site:unternehmensregister.de OR site:handelsregisterbekanntmachungen.de "{clean_name}"',
                "desc": "Öffentliche Bekanntmachungen des Bundesanzeigers."
            },
            {
                "title": "Business Netzwerke (LinkedIn / Xing)",
                "query": f'(site:linkedin.com/in/ OR site:xing.com/profile/) "{clean_name}"',
                "desc": "Öffentlich indexierte Profile auf Berufsnetzwerken."
            }
        ]
        dorks.append({
            "category": "🏢 Register & Geschäftsaktivitäten",
            "items": queries_cat2
        })

    # Category 3: Freiliegende Dokumente & PDFs
    target_ident = clean_name or clean_username or clean_email
    if target_ident:
        queries_cat3 = [
            {
                "title": "Dokumenten-Fund (PDF, Excel, Word)",
                "query": f'"{target_ident}" (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)',
                "desc": "Findet offene Teilnehmerlisten, Rechnungen, Vereinslisten oder Protokolle."
            },
            {
                "title": "Vereine & Organisationen",
                "query": f'"{target_ident}" (inurl:verein OR inurl:vorstand OR inurl:protokoll)',
                "desc": "Ehrenamtliche oder vereinsbezogene Veröffentlichungen."
            }
        ]
        dorks.append({
            "category": "📄 Dokumente & Vereinslisten",
            "items": queries_cat3
        })

    # Category 4: Leaks, Pastes & Foren
    if clean_username or clean_email:
        ident = clean_email or clean_username
        queries_cat4 = [
            {
                "title": "Pastebin & Dump-Seiten",
                "query": f'(site:pastebin.com OR site:justpaste.it OR site:ghostbin.com) "{ident}"',
                "desc": "Geleakte Textdateien, Logs oder Konfigurationsdaten."
            },
            {
                "title": "Alte Foren & Diskussionen",
                "query": f'"{clean_username or ident}" (inurl:forum OR inurl:thread OR inurl:topic)',
                "desc": "Alte Forenbeiträge aus vergangenen Jahren."
            },
            {
                "title": "Sensible Daten & Passwörter",
                "query": f'"{ident}" (intext:password OR intext:passwort OR intext:passwd)',
                "desc": "Unverschlüsselte Anmeldedaten in öffentlichen Repositories oder Textdateien."
            }
        ]
        dorks.append({
            "category": "🛡️ Foren, Leaks & Dump-Seiten",
            "items": queries_cat4
        })

    # Add Google search URL to all items
    for cat in dorks:
        for item in cat["items"]:
            encoded_query = urllib.parse.quote_plus(item["query"])
            item["google_url"] = f"https://www.google.com/search?q={encoded_query}"

    return dorks
