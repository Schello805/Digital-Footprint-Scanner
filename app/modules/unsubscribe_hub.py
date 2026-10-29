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
    },
    {
        "name": "Yasni (People Search Directory)",
        "category": "People Search & Web Directory",
        "desc_de": "Aggregiert Webseiten, Profile und Personendaten unter deinem Klarnamen.",
        "desc_en": "Aggregates web pages, public records, and directories under real names.",
        "opt_out_url": "https://www.yasni.de/kontakt",
        "privacy_email": "info@yasni.de",
        "method": "email_and_web"
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

    # Guard: Prevent sending GDPR objection to the user's own domain
    if "@" in clean_target and "@" in clean_email:
        target_domain = clean_target.split("@")[1]
        user_domain = clean_email.split("@")[1]
        if user_domain and target_domain and user_domain == target_domain:
            msg_de = f"Die Zieladresse ({clean_target}) liegt auf deiner eigenen Domain ({user_domain}). Ein Werbewiderspruch an sich selbst ist nicht sinnvoll."
            msg_en = f"The target address ({clean_target}) belongs to your own domain ({user_domain}). You cannot send a GDPR objection to yourself."
            return {
                "success": False,
                "error": msg_de if lang == "de" else msg_en,
                "is_own_domain": True
            }

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

    # Detect category & provide forensic info
    matched_broker = None
    for b in MARKETING_LIST_BROKERS:
        if b["name"].lower() in clean_target or (b["privacy_email"] and b["privacy_email"] in clean_target) or (b.get("opt_out_url") and urllib.parse.urlparse(b["opt_out_url"]).netloc in clean_target):
            matched_broker = b
            break

    if matched_broker:
        detected_category_de = f"Kuratierter Datenbroker: {matched_broker['name']}"
        detected_category_en = f"Curated Data Broker: {matched_broker['name']}"
        detected_type = "broker"
        legal_summary_de = "Bedingungsloser Widerspruchsanspruch gegen Adresshandel und Profilbildung gem. Art. 21 Abs. 2 DSGVO i.V.m. Löschung nach Art. 17 DSGVO."
        legal_summary_en = "Unconditional right to object against data brokering & audience profiling under Art. 21(2) & erasure under Art. 17 GDPR."
        protocol_summary_de = f"Direkter Datenschutzbeauftragten-Kontakt ({matched_broker['privacy_email']}) oder zentrales Opt-Out-Portal."
        protocol_summary_en = f"Direct Data Protection Officer contact ({matched_broker['privacy_email']}) or central web opt-out portal."
        if matched_broker.get("privacy_email"):
            target_mail_recipient = matched_broker["privacy_email"]
            gdpr_mailto = f"mailto:{target_mail_recipient}?subject={urllib.parse.quote(gdpr_subject)}&body={urllib.parse.quote(gdpr_body)}"
        if matched_broker.get("opt_out_url"):
            web_options_url = matched_broker["opt_out_url"]
    elif "list" in clean_target or "mailman" in domain or "groups" in domain or "-request" in clean_target:
        detected_category_de = "RFC 2369 Mailinglisten-Server (Mailman / Sympa / Ezmlm)"
        detected_category_en = "RFC 2369 Mailing List Daemon (Mailman / Sympa / Ezmlm)"
        detected_type = "rfc_list"
        legal_summary_de = "Automatisierter Listenserver-Widerruf (RFC 2369) und ergänzender DSGVO Art. 17 Löschanspruch aus den Verteilerarchiven."
        legal_summary_en = "Automated list daemon revocation (RFC 2369) and supplementary GDPR Art. 17 erasure request from list archives."
        protocol_summary_de = f"Automatischer Listen-Daemon: <{mailman_req_email}> verarbeitet 'unsubscribe' ohne menschlichen Support."
        protocol_summary_en = f"Automated list daemon: <{mailman_req_email}> parses 'unsubscribe' commands without manual intervention."
    else:
        detected_category_de = "Kommerzieller Newsletter- & Direktmarketing-Verteiler"
        detected_category_en = "Commercial Newsletter & Direct Marketing Distribution"
        detected_type = "newsletter"
        legal_summary_de = "Gesetzliches Werbewiderspruchsrecht nach Art. 21 Abs. 2 DSGVO und § 7 Abs. 3 UWG. Keine Kündigungsfristen oder Begründung erforderlich."
        legal_summary_en = "Statutory objection right to direct marketing under Art. 21(2) GDPR. No cancellation notice period or justification required."
        protocol_summary_de = "Direktwerbe-Widerspruch per 1-Klick-Mail an Datenschutzbeauftragten oder Absenderadresse."
        protocol_summary_en = "1-Click direct marketing objection email to privacy officer or sender address."

    # Webmail compose URLs for users without configured desktop mail client
    active_mail = mailman_req_email if detected_type == "rfc_list" else target_mail_recipient
    active_subj = rfc_subject if detected_type == "rfc_list" else gdpr_subject
    active_body = rfc_body if detected_type == "rfc_list" else gdpr_body
    gmail_url = f"https://mail.google.com/mail/?view=cm&fs=1&to={urllib.parse.quote(active_mail)}&su={urllib.parse.quote(active_subj)}&body={urllib.parse.quote(active_body)}"
    outlook_url = f"https://outlook.live.com/mail/0/deeplink/compose?to={urllib.parse.quote(active_mail)}&subject={urllib.parse.quote(active_subj)}&body={urllib.parse.quote(active_body)}"

    return {
        "success": True,
        "data": {
            "target": clean_target,
            "user_email": clean_email,
            "user_name": name_str,
            "detected_type": detected_type,
            "detected_category_de": detected_category_de,
            "detected_category_en": detected_category_en,
            "legal_summary_de": legal_summary_de,
            "legal_summary_en": legal_summary_en,
            "protocol_summary_de": protocol_summary_de,
            "protocol_summary_en": protocol_summary_en,
            "primary_recipient": active_mail,
            "mailman_request_email": mailman_req_email,
            "rfc_subject": rfc_subject,
            "rfc_body": rfc_body,
            "rfc_mailto": rfc_mailto,
            "web_options_url": web_options_url,
            "gdpr_subject": gdpr_subject,
            "gdpr_body": gdpr_body,
            "gdpr_mailto": gdpr_mailto,
            "gmail_url": gmail_url,
            "outlook_url": outlook_url,
            "marketing_brokers": MARKETING_LIST_BROKERS
        }
    }

def generate_batch_broker_optout_package(
    user_email: str,
    user_name: str = "",
    user_phone: str = "",
    user_city: str = "",
    lang: str = "de"
) -> Dict[str, Any]:
    """
    Generates a 1-click batch opt-out package to contact all curated data brokers simultaneously
    using a multi-recipient BCC email pursuant to Art. 21(2) & Art. 17 GDPR.
    """
    clean_email = user_email.strip().lower()
    name_str = user_name.strip() or ("Betroffene Person" if lang == "de" else "Concerned Individual")
    clean_phone = user_phone.strip()
    clean_city = user_city.strip()

    # Collect all broker privacy contacts
    email_brokers = [b for b in MARKETING_LIST_BROKERS if b.get("privacy_email")]
    broker_emails = [b["privacy_email"] for b in email_brokers]

    if not broker_emails:
        primary_to = ""
        bcc_list = []
    else:
        primary_to = broker_emails[0]
        bcc_list = broker_emails[1:]

    phone_line_de = f"\n- Telefon / Mobilfunk: {clean_phone}" if clean_phone else ""
    city_line_de = f"\n- Wohnort / Region: {clean_city}" if clean_city else ""
    
    phone_line_en = f"\n- Phone Number: {clean_phone}" if clean_phone else ""
    city_line_en = f"\n- City / Region: {clean_city}" if clean_city else ""

    if lang == "de":
        subject = f"Widerspruch gem. Art. 21 Abs. 2 DSGVO & Löschung gem. Art. 17 DSGVO ({clean_email})"
        body = f"""Sehr geehrte Damen und Herren Datenschutzbeauftragte,

hiermit widerspreche ich gemäß Art. 21 Abs. 2 DSGVO bei allen angeschriebenen Auskunfteien, Adress- und Datenbrokern der Verarbeitung und Nutzung meiner personenbezogenen Daten für Zwecke der Direktwerbung, des Adresshandels, der Profilbildung und des Marketings.

Zu meiner Person gehören folgende Identifikatoren:
- E-Mail-Adresse: {clean_email}
- Name: {name_str}{phone_line_de}{city_line_de}

Ich fordere Sie hiermit auf:
1. Meine personenbezogenen Daten unverzüglich aus all Ihren Datenbanken, Profilen, Verteilerlisten und Scoringsystemen zu löschen (Art. 17 Abs. 1 lit. c DSGVO).
2. Etwaige Datenempfänger, an die meine Daten übermittelt wurden, unverzüglich über dieses Löschbegehren zu unterrichten (Art. 17 Abs. 2 DSGVO).
3. Mir die vollständige Durchführung der Löschung schriftlich innerhalb der gesetzlichen Frist von einem Monat (Art. 12 Abs. 3 DSGVO) zu bestätigen.

Mit freundlichen Grüßen,
{name_str}"""
    else:
        subject = f"Multi-Broker Opt-Out under Art. 21(2) & Erasure under Art. 17 GDPR ({clean_email})"
        body = f"""To Whom It May Concern (Data Protection Officers),

Pursuant to Article 21(2) of the General Data Protection Regulation (GDPR) and applicable privacy legislation, I hereby object to the processing of my personal data for direct marketing, consumer profiling, address brokering, and commercial distribution across all contacted data brokers.

My personal identifying records are:
- Email Address: {clean_email}
- Full Name: {name_str}{phone_line_en}{city_line_en}

I hereby demand that you:
1. Permanently erase all my personal data from your databases, marketing lists, audience segments, and web indexes without undue delay (Art. 17(1)(c) GDPR).
2. Notify all third-party recipients to whom my personal data was disclosed of this erasure request (Art. 17(2) GDPR).
3. Confirm the complete execution of this erasure in writing within the statutory deadline of one month (Art. 12(3) GDPR).

Sincerely,
{name_str}"""

    bcc_param = f"&bcc={urllib.parse.quote(','.join(bcc_list))}" if bcc_list else ""
    batch_mailto = f"mailto:{primary_to}?subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}{bcc_param}"

    bcc_str = ','.join(bcc_list)
    gmail_url = f"https://mail.google.com/mail/?view=cm&fs=1&to={urllib.parse.quote(primary_to)}&su={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}{('&bcc=' + urllib.parse.quote(bcc_str)) if bcc_str else ''}"
    outlook_url = f"https://outlook.live.com/mail/0/deeplink/compose?to={urllib.parse.quote(primary_to)}&subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}{('&bcc=' + urllib.parse.quote(bcc_str)) if bcc_str else ''}"

    return {
        "success": True,
        "data": {
            "user_email": clean_email,
            "user_name": name_str,
            "primary_to": primary_to,
            "bcc_emails": bcc_list,
            "all_broker_emails": broker_emails,
            "brokers_count": len(email_brokers),
            "brokers_included": email_brokers,
            "subject": subject,
            "body": body,
            "batch_mailto": batch_mailto,
            "gmail_url": gmail_url,
            "outlook_url": outlook_url
        }
    }
