import re
import urllib.parse
from typing import Dict, Any

GERMAN_AREA_CODES = {
    "030": "Berlin",
    "040": "Hamburg",
    "089": "München",
    "069": "Frankfurt am Main",
    "0221": "Köln",
    "0711": "Stuttgart",
    "0211": "Düsseldorf",
    "0341": "Leipzig",
    "0231": "Dortmund",
    "0201": "Essen",
    "0421": "Bremen",
    "0351": "Dresden",
    "0511": "Hannover",
    "0911": "Nürnberg",
    "0202": "Wuppertal",
    "0228": "Bonn",
    "0251": "Münster",
    "0721": "Karlsruhe",
    "0621": "Mannheim",
    "0821": "Augsburg"
}

MOBILE_PREFIXES = {
    "0151": "Telekom (D1)",
    "0160": "Telekom (D1)",
    "0170": "Telekom (D1)",
    "0171": "Telekom (D1)",
    "0175": "Telekom (D1)",
    "0152": "Vodafone (D2)",
    "0162": "Vodafone (D2)",
    "0172": "Vodafone (D2)",
    "0173": "Vodafone (D2)",
    "0174": "Vodafone (D2)",
    "0157": "Telefónica / O2 (E-Plus)",
    "0163": "Telefónica / O2 (E-Plus)",
    "0177": "Telefónica / O2 (E-Plus)",
    "0178": "Telefónica / O2 (E-Plus)",
    "0159": "Telefónica / O2",
    "0176": "Telefónica / O2",
    "0155": "1&1 Mobilfunk",
}

def analyze_phone_number(raw_phone: str) -> Dict[str, Any]:
    cleaned = re.sub(r'[\s\-\/\(\)]', '', raw_phone.strip())
    
    # Normalize German +49 or 0049 to 0
    if cleaned.startswith("+49"):
        cleaned_de = "0" + cleaned[3:]
    elif cleaned.startswith("0049"):
        cleaned_de = "0" + cleaned[4:]
    else:
        cleaned_de = cleaned

    number_type = "Unbekannt"
    provider_or_city = "Nicht ermittelt"
    is_mobile = False

    # Check mobile
    for prefix, name in MOBILE_PREFIXES.items():
        if cleaned_de.startswith(prefix):
            number_type = "Mobilfunknetz"
            provider_or_city = name
            is_mobile = True
            break

    # Check landline
    if not is_mobile:
        for code, city in GERMAN_AREA_CODES.items():
            if cleaned_de.startswith(code):
                number_type = "Festnetz"
                provider_or_city = f"Ortsnetz {city}"
                break

    # Reverse lookup & OSINT links
    encoded_phone = urllib.parse.quote_plus(raw_phone)
    encoded_clean = urllib.parse.quote_plus(cleaned_de)
    
    lookup_links = [
        {
            "name": "Google Telefonspuren",
            "url": f'https://www.google.com/search?q="{encoded_clean}"+OR+"{encoded_phone}"',
            "desc": "Findet Einträge in Vereinslisten, PDF-Rechnungen oder Foren."
        },
        {
            "name": "Tellows (Spam- & Score-Check)",
            "url": f"https://www.tellows.de/num/{cleaned_de}",
            "desc": "Prüft, ob die Nummer in Spam-Listen gemeldet oder indexiert ist."
        },
        {
            "name": "Das Örtliche (Telefonbuch)",
            "url": f"https://www.dasoertliche.de/?kw={cleaned_de}",
            "desc": "Rückwärtssuche in offiziellen deutschen Verzeichnissen."
        }
    ]

    return {
        "raw": raw_phone,
        "normalized": cleaned_de,
        "type": number_type,
        "region_or_carrier": provider_or_city,
        "is_mobile": is_mobile,
        "lookup_links": lookup_links
    }
