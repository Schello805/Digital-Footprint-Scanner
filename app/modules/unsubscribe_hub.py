import re
import urllib.parse
from typing import Dict, Any, List, Optional

# Incogni-style curated marketing list and data broker opt-out registry
MARKETING_LIST_BROKERS: List[Dict[str, Any]] = [
    {
        "name": "Schober Information Group (DACH)",
        "category": "Direct Marketing & B2B/B2C Lists",
        "desc_de": "Einer der größten Adress- und Marketingdaten-Händler im DACH-Raum.",
        "desc_en": "Major address and direct marketing list broker in the DACH region.",
        "opt_out_url": "https://www.schober.de/datenschutz/",
        "privacy_email": "datenschutz@schober.de",
        "method": "email_and_web"
    },
    {
        "name": "microm Consumer Marketing (DACH)",
        "category": "Consumer & Geotargeting Lists",
        "desc_de": "Liefert Zielgruppen- und Wohnumfeld-Daten für Direktwerbung.",
        "desc_en": "Provides consumer target audience data for commercial direct marketing.",
        "opt_out_url": "https://www.microm.de/datenschutz",
        "privacy_email": "datenschutz@microm.de",
        "method": "email"
    },
    {
        "name": "Acxiom (Global Marketing Data)",
        "category": "Data Broker & Audience Lists",
        "desc_de": "Weltweiter Daten- und Werbe-Aggregator für Personenprofile.",
        "desc_en": "Global data aggregator and consumer marketing broker.",
        "opt_out_url": "https://www.acxiom.de/datenschutz-uebersicht/",
        "privacy_email": "datenschutz@acxiom.com",
        "method": "web_portal"
    },
    {
        "name": "LiveRamp (Identity Resolution)",
        "category": "AdTech & Identity Linking",
        "desc_de": "Verknüpft E-Mail-Adressen mit Werbeprofilen und Tracking-Netzwerken.",
        "desc_en": "Resolves offline email identities to cross-web advertising profiles.",
        "opt_out_url": "https://liveramp.de/datenschutz/opt-out/",
        "privacy_email": "datenschutz@liveramp.com",
        "method": "web_portal"
    },
    {
        "name": "Criteo (Email & Retargeting)",
        "category": "Commerce & Email Targeting",
        "desc_de": "Werbenetzwerk zur zielgerichteten Ansprache per Mail und Web.",
        "desc_en": "Commercial retargeting and personalized email marketing network.",
        "opt_out_url": "https://www.criteo.com/de/privacy/disable-criteo-services-on-internet-browsers/",
        "privacy_email": "dpo@criteo.com",
        "method": "web_portal"
    },
    {
        "name": "Experian Marketing Services",
        "category": "Credit & Marketing Aggregator",
        "desc_de": "Aggregiert Konsumentenprofile für personalisierte Mailkampagnen.",
        "desc_en": "Aggregates consumer lists and demographic data for commercial mailings.",
        "opt_out_url": "https://www.experian.de/service/datenschutz",
        "privacy_email": "datenschutz@experian.de",
        "method": "email"
    }
]

def generate_unsubscribe_package(
    list_identifier: str,
    user_email: str,
    user_name: str = "",
    lang: str = "de"
) -> Dict[str, Any]:
    """
    Generates automated RFC 2369 / GNU Mailman commands, web administration links,
    and GDPR Art. 17 / 21 objection emails for 1-click unsubscribe.
    """
    clean_target = list_identifier.strip().lower()
    clean_email = user_email.strip().lower()
    name_str = user_name.strip() or ("Betroffene Person" if lang == "de" else "Concerned Individual")

    local_part = ""
    domain = ""
    
    if "@" in clean_target:
        parts = clean_target.split("@", 1)
        local_part = parts[0]
        domain = parts[1]
    else:
        local_part = clean_target
        domain = "lists.example.org"

    # 1. RFC 2369 / GNU Mailman automated command email
    # Mailman lists support <listname>-request@domain with subject 'unsubscribe'
    mailman_req_email = f"{local_part}-request@{domain}" if domain else ""
    rfc_subject = "unsubscribe"
    rfc_body = f"unsubscribe {clean_email}" if clean_email else "unsubscribe"
    
    rfc_mailto = ""
    if mailman_req_email:
        rfc_mailto = f"mailto:{mailman_req_email}?subject={urllib.parse.quote(rfc_subject)}&body={urllib.parse.quote(rfc_body)}"

    # Mailman web options URL (standard archive/options unsubscription path)
    web_options_url = ""
    if domain and local_part:
        web_options_url = f"https://{domain}/mailman/options/{local_part}"

    # 2. Formal GDPR Art. 21 Objection & Art. 17 Erasure Request
    if lang == "de":
        gdpr_subject = f"Widerspruch gem. Art. 21 DSGVO & Austragung aus Verteiler ({clean_email})"
        gdpr_body = f"""Sehr geehrte Damen und Herren,

hiermit widerspreche ich gemäß Art. 21 Abs. 2 DSGVO der Verarbeitung und Nutzung meiner personenbezogenen Daten für Zwecke der Direktwerbung, des Marketings und der Zusendung von Newslettern oder Rundschreiben.

Bitte tragen Sie meine E-Mail-Adresse:
{clean_email}

unverzüglich aus allen Ihren Mailinglisten, Verteilern und Datenbanken aus und löschen Sie meine Daten gemäß Art. 17 DSGVO.

Bitte bestätigen Sie mir die vollständige Löschung und den Vollzug dieses Widerspruchs schriftlich.

Mit freundlichen Grüßen,
{name_str}"""
    else:
        gdpr_subject = f"Opt-Out Request pursuant to Art. 21 GDPR & List Unsubscribe ({clean_email})"
        gdpr_body = f"""To Whom It May Concern,

Pursuant to Article 21(2) of the General Data Protection Regulation (GDPR) and applicable privacy laws, I hereby object to the processing of my personal data for direct marketing, distribution lists, and automated newsletter communications.

Please permanently unsubscribe and erase my email address:
{clean_email}

from all of your mailing lists, subscriber databases, and commercial distribution directories without undue delay (Art. 17 GDPR).

Please confirm the execution of this unsubscription in writing.

Sincerely,
{name_str}"""

    # Direct mailto for general privacy/list email
    target_mail_recipient = clean_target if "@" in clean_target else f"privacy@{domain}" if domain else ""
    gdpr_mailto = ""
    if target_mail_recipient:
        gdpr_mailto = f"mailto:{target_mail_recipient}?subject={urllib.parse.quote(gdpr_subject)}&body={urllib.parse.quote(gdpr_body)}"

    return {
        "success": True,
        "data": {
            "target": clean_target,
            "user_email": clean_email,
            "mailman_request_email": mailman_req_email,
            "rfc_subject": rfc_subject,
            "rfc_body": rfc_body,
            "rfc_mailto": rfc_mailto,
            "web_options_url": web_options_url,
            "gdpr_subject": gdpr_subject,
            "gdpr_body": gdpr_body,
            "gdpr_mailto": gdpr_mailto,
            "marketing_brokers": MARKETING_LIST_BROKERS
        }
    }
