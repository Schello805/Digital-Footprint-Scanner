// Global State & i18n
let currentLang = localStorage.getItem('selfscanner_lang') || 'en';
let currentTab = 'fullscan';
let fullScanProfiles = [];
let lastScanResult = null;
let lastScanPayload = null;
let usernameEventSource = null;
let currentResults = [];
let leafletMap = null;
let leafletMarker = null;
let currentSelectedFile = null;

// ==================== I18N DICTIONARY ====================
const translations = {
  en: {
    app_title: "Digital Footprint Scanner",
    app_subtitle: "All-in-One OSINT Suite",
    tagline: "Holistic digital footprint reconnaissance without detours",
    fullscan_cockpit: "🚀 Full Scan Cockpit",
    api_keys: "⚙️ API Keys",
    tab_fullscan: "🚀 Full Scan (All-in-One)",
    tab_scans: "📁 My Scans",
    gate_title: "Digital Footprint Scanner",
    gate_desc: "Create a free account to scan your digital footprint. All results and reports remain saved in your profile.",
    tab_exif: "📸 EXIF Photo Inspector",
    tab_username: "👤 Username Recon",
    tab_domain: "🌐 Domain & DNS Security",
    tab_breach: "🛡️ Password & Breach Check",
    tab_dorks: "🔎 Google Dorking",
    cockpit_title: "Automated Full Scan",
    cockpit_badge: "1-Click Full Audit",
    cockpit_desc: "Enter your identifiers once. The scanner concurrently checks social accounts, data breaches, phone reputation, mail spoofing, and automatically filters out coincidental name matches.",
    no_mandatory: "No mandatory fields except Name or Username",
    lbl_name: "Full Name",
    lbl_first_name: "First Name",
    lbl_last_name: "Last Name",
    lbl_username: "Username / Handle",
    lbl_email: "Email Address",
    lbl_password: "Password (Leak Check)",
    lbl_city: "City / Location",
    lbl_employer: "Company / Employer",
    lbl_phone: "Phone / Mobile",
    lbl_domain: "Domain (Mail Security)",
    cockpit_footer_note: "Concurrently queries k-Anonymity hashes, verified social platforms, mail spoofing & dorks.",
    btn_start_fullscan: "🚀 Start Full Scan (Audit Everything)",
    dossier_created_title: "Complete Intelligence Dossier Generated",
    btn_print_dossier: "📄 Print DIN A4 Dossier / PDF",
    btn_toggle_view: "Toggle View",
    sec_profile_sheet: "📋 Target Profile Sheet",
    field_name: "Full Name:",
    field_city: "City / Region:",
    field_employer: "Employer / Org:",
    field_email: "Primary Email:",
    field_phone: "Phone / Carrier:",
    field_domain: "Personal Domain:",
    stamp_subtext: "Calculated via OSINT attack surface",
    sec_1_title: "1. Security Analysis & Breach Status",
    card_pwd_integrity: "🔑 Password Integrity:",
    card_email_breaches: "📬 Email Data Breaches:",
    card_domain_security: "🌐 Domain Mail Spoofing:",
    sec_2_title: "2. Websites & Online Presences Where You Appear",
    th_platform: "Platform",
    th_category: "Category",
    th_verification: "Verification Status",
    th_bio: "Extracted Bio Snippet / Note",
    th_link: "Profile Link",
    sec_3_title: "3. Forensic Threat Vector Analysis (Social Engineering & Doxing)",
    sec_comm_title: "4. Verified Communication Channels & Infrastructure Audit",
    sec_phone_recon: "📞 Phone Network & Routing (ITU/BNetzA)",
    sec_mailing_lists: "📬 Mailing Lists & Discussion Archives",
    sec_email_audit: "✉️ Verified Email Address & MX Routing",
    sec_dorks_title: "5. Public Registries & Document Trails (Registers, Leaks, PDFs)",
    sec_dorks_sub: "Click links below to open direct search queries across registries (North Data, Bundesanzeiger) and public document dumps without bot blocks:",
    sec_cleanup_title: "🛡️ 6. Footprint Remediation & Account Deletion (Action Plan)",
    sec_cleanup_sub: "Direct account deactivation links",
    broker_title: "Preventative Directory & Phone Book Opt-Out (Precautionary):",
    sec_gdpr_title: "7. Legal Remediation: Art. 17 GDPR Erasure Request ('Right to be Forgotten')",
    gdpr_desc: "Use this legally binding letter to request immediate erasure of your personal data from platform operators, databases, and search engines.",
    btn_copy_text: "Copy Text",
    google_removal_link: "Submit official Google Search Removal Request ↗",
    exif_title: "Metadata & EXIF Inspector",
    exif_desc: "Upload a photo. We analyze hidden GPS coordinates, camera models, timestamps and provide a 1-click privacy sanitizer.",
    exif_drop_text: "Drop photo here or click to browse",
    btn_sanitize_download: "🛡️ Clean Image & Download without EXIF",
    exif_risk_assessment: "Privacy Risk Assessment",
    exif_loc_found: "📍 Exposed Capture Location",
    sensitive_data: "Sensitive Data",
    exif_tags_title: "Extracted Metadata Tags",
    th_property: "Property",
    th_value: "Value",
    user_recon_title: "Single Username Recon (Sherlock)",
    user_recon_desc: "Search for registered profiles and active online accounts under this handle.",
    lbl_profiles_found: "Discovered Profiles:",
    btn_start_scan: "Start Scan",
    dom_title: "Domain & Mail Security Audit",
    btn_scan_domain: "Scan Domain",
    pwd_check_title: "Password Leak Check (k-Anonymity)",
    btn_check: "Check",
    email_check_title: "Email Data Breach Check",
    dorks_title: "Google Dorking Generator",
    btn_generate_dorks: "Generate Queries",
    settings_title: "⚙️ Optional API Keys",
    settings_desc: "All core features run 100% free. If you have an official HaveIBeenPwned API key or Google Custom Search key, configure them here.",
    btn_back_to_cockpit: "To Full Scan Cockpit",
    btn_save: "Save Settings",
    classification_tag: "OSINT PRIVACY AUDIT // PERSONAL INTELLIGENCE DOSSIER",
    confidential_tag: "CONFIDENTIAL // PRIVATE SECURITY AUDIT USE ONLY",
    file_ref_prefix: "FILE REFERENCE: AZ-OSINT-2026-",
    audit_result_label: "AUDIT RESULT",
    risk_label_prefix: "RISK: ",
    link_legal_disclaimer: "⚖️ Legal Disclaimer & Terms of Use",
    modal_disclaimer_title: "Legal Notice, Ethical Use & Terms of Service",
    btn_close_disclaimer: "Understood & Acknowledge",
    tab_unsubscribe: "📬 Unsubscribe Hub (Incogni-Style)",
    unsub_hub_title: "Mailing List & Marketing Opt-Out Hub",
    unsub_hub_desc: "Unsubscribe from persistent mailing lists, spam distribution lists, and commercial direct marketing data brokers with 1-click RFC 2369 automation commands and legally binding Art. 21 & Art. 17 GDPR objection letters.",
    unsub_form_title: "Target List & Mail Details",
    unsub_form_subtitle: "Enter the mailing list address or sender you want to unsubscribe from.",
    lbl_unsub_target: "Mailing List or Sender Address",
    lbl_unsub_email: "Your Email Address (To Unsubscribe)",
    lbl_unsub_name: "Your Name (Optional, for GDPR Letter)",
    btn_gen_unsub: "Generate 1-Click Unsubscribe Package",
    tip_rfc_title: "How RFC 2369 Unsubscribe Works:",
    tip_rfc_desc: "Standard mailing lists (Mailman, Majordomo, Sympa) run automated server daemons. Sending an email with the subject unsubscribe to <list>-request@... removes you automatically without human intervention.",
    unsub_actions_title: "1-Click Unsubscribe Actions",
    lbl_letter_preview: "Formal GDPR Objection & Erasure Text (Pre-populated)",
    btn_copy_letter: "Copy Letter",
    brokers_catalog_title: "Direct Marketing & Broker Opt-Out Directory",
    brokers_catalog_sub: "Opt-out directly from large consumer data aggregators and address brokers that fuel commercial cold-mailings and lead lists.",
    step1_title: "1. Input",
    step1_sub: "Select list or broker",
    step2_title: "2. Info & Analysis",
    step2_sub: "Type, DPO & Legal Basis",
    step3_title: "3. Action & Status",
    step3_sub: "Opt-out & Log Status",
    unsub_step1_manual_title: "Option A: Custom List or Sender",
    unsub_step1_manual_sub: "Enter the address of the unwanted mailing list or newsletter.",
    unsub_found_from_scan: "Mailing lists detected in scan:",
    btn_use_scan_email: "Use email from scan",
    btn_next_step2: "🔍 Proceed to Step 2: Info & Analysis ➔",
    unsub_step1_broker_title: "Option B: Quick-Select Top Data Brokers",
    unsub_step1_broker_sub: "Click a broker to immediately load it into Step 2:",
    step2_header_title: "Forensic Classification & Legal Basis",
    btn_edit_target: "Edit input",
    card_detected_type_title: "1. Detected Type & Protocol",
    card_legal_basis_title: "2. Statutory Legal Grounds",
    card_routing_title: "3. Discovered Contact Points",
    btn_back_step1: "⬅ Back to Step 1 (Input)",
    btn_next_step3: "⚡ Proceed to Step 3: Execute Action ➔",
    step3_header_title: "Immediate Action & Status Tracking",
    act_primary_mail_title: "1. Email Unsubscription",
    act_web_title: "2. Web Opt-Out Portal",
    act_copy_title: "3. Copy Letter",
    status_tracker_title: "Incogni-Style Status Tracker for this Request:",
    btn_back_step2: "⬅ Back to Step 2 (Info)",
    btn_new_unsub: "Unsubscribe another list or broker",
    batch_broker_title: "Contact All 7 Data Brokers in 1 Click",
    batch_broker_sub: "Generates a confidential BCC email to all data protection officers (Schober, microm, Acxiom, LiveRamp, Criteo, Experian, Yasni) simultaneously.",
    btn_batch_mailto: "Open 1-Click Multi-Broker Email (BCC)",
    btn_mark_all_sent: "Mark all 7 as 'Request Dispatched'",
    btn_batch_optout_short: "Contact all Data Brokers in 1 Click (Batch Opt-Out)"
  },
  de: {
    app_title: "Digital Footprint Scanner",
    app_subtitle: "All-in-One OSINT Suite",
    tagline: "Ganzheitlicher digitaler Fußabdruck-Scan ohne Umwege",
    fullscan_cockpit: "🚀 Vollscan Cockpit",
    api_keys: "⚙️ API-Keys",
    tab_fullscan: "🚀 Vollscan (Alles auf einmal)",
    tab_scans: "📁 Meine Scans",
    gate_title: "Digital Footprint Scanner",
    gate_desc: "Kostenlos registrieren, um deinen digitalen Fußabdruck zu scannen. Alle Funde und Berichte bleiben dauerhaft in deinem Profil gesichert.",
    tab_exif: "📸 EXIF-Foto-Inspektor",
    tab_username: "👤 Einzelner Username-Check",
    tab_domain: "🌐 Domain & DNS-Security",
    tab_breach: "🛡️ Passwort- & Breach-Check",
    tab_dorks: "🔎 Google Dorking",
    cockpit_title: "Automatisierter Vollscan",
    cockpit_badge: "1-Klick Komplett-Audit",
    cockpit_desc: "Gib einmal deine Daten ein. Der Scanner prüft gleichzeitig Social-Media-Accounts, Datenpannen, Rufnummern, Mail-Spoofing, Register und filtert fremde Namensvetter automatisch aus.",
    no_mandatory: "Keine Pflichtfelder außer Name oder Username",
    lbl_name: "Vor- & Nachname",
    lbl_first_name: "Vorname",
    lbl_last_name: "Nachname / Zuname",
    lbl_username: "Benutzername / Alias",
    lbl_email: "E-Mail-Adresse",
    lbl_password: "Passwort (Leak-Check)",
    lbl_city: "Wohnort / Stadt",
    lbl_employer: "Firma / Arbeitgeber",
    lbl_phone: "Telefon / Handy",
    lbl_domain: "Eigene Domain (Mail-Security)",
    cockpit_footer_note: "Prüft k-Anonymity Hashes, verifizierte Plattform-Accounts, Mail-Spoofing & Dorks gleichzeitig.",
    btn_start_fullscan: "🚀 Vollscan starten (Alles prüfen)",
    dossier_created_title: "Vollständiges Personen-Dossier erstellt",
    btn_print_dossier: "📄 Als DIN A4 Steckbrief drucken / PDF",
    btn_toggle_view: "Ansicht umschalten",
    sec_profile_sheet: "📋 Stammdatenblatt",
    field_name: "Klarname:",
    field_city: "Wohnort / Region:",
    field_employer: "Firma / Arbeitgeber:",
    field_email: "Primäre E-Mail:",
    field_phone: "Rufnummer / Netz:",
    field_domain: "Eigene Domain:",
    stamp_subtext: "Berechnet nach OWASP/OSINT Angriffsfläche",
    sec_1_title: "1. Sicherheitsanalyse & Kompromittierungs-Status (Breaches)",
    card_pwd_integrity: "🔑 Passwort-Integrität:",
    card_email_breaches: "📬 E-Mail Datenpannen:",
    card_domain_security: "🌐 Domain Mail-Spoofing:",
    sec_2_title: "2. Webseiten & Online-Präsenzen, auf denen du erscheinst",
    th_platform: "Plattform",
    th_category: "Kategorie",
    th_verification: "Verifikations-Status",
    th_bio: "Gefundener Bio-Auszug / Notiz",
    th_link: "Profil-Link",
    sec_3_title: "3. Forensische Bedrohungsanalyse (Social Engineering & Doxing)",
    sec_comm_title: "4. Verifizierte Kommunikationskanäle & Infrastruktur-Audit",
    sec_phone_recon: "📞 Telefonnetz & Routing (ITU/BNetzA)",
    sec_mailing_lists: "📬 Mailinglisten & Diskussionsarchive",
    sec_email_audit: "✉️ Verifizierte E-Mail-Adresse & MX-Routing",
    sec_dorks_title: "5. Öffentliche Register & Spurensuche (Handelsregister, PDFs, North Data)",
    sec_dorks_sub: "Klicke auf die Links, um Suchergebnisse in Registern (North Data, Bundesanzeiger) und Foren ohne Bot-Sperren direkt zu prüfen:",
    sec_cleanup_title: "🛡️ 6. Footprint-Bereinigung & Account-Löschung (Action Plan)",
    sec_cleanup_sub: "Direkt-Links zur Kontodeaktivierung",
    broker_title: "Vorsorgliche Austragung aus Telefon- & Auskunftsverzeichnissen (Opt-Out):",
    sec_gdpr_title: "7. Rechtliche Sofortmaßnahme: Art. 17 DSGVO Löschanforderung („Recht auf Vergessenwerden“)",
    gdpr_desc: "Nutze diesen vorgefertigten Rechtstext, um Plattformen, Register und Suchmaschinen zur vollständigen Löschung deiner personenbezogenen Daten nach Art. 17 DSGVO aufzufordern.",
    btn_copy_text: "Text kopieren",
    google_removal_link: "Offiziellen Google-Suchergebnis-Entfernungsantrag einreichen ↗",
    exif_title: "Metadaten- & EXIF-Inspektor",
    exif_desc: "Lade ein Foto hoch. Wir analysieren GPS-Koordinaten, Kameramodell und bieten dir einen 1-Klick-Datenschutz-Bereiniger.",
    exif_drop_text: "Foto hier hineinziehen oder klicken",
    btn_sanitize_download: "🛡️ Bild bereinigen & ohne EXIF herunterladen",
    exif_risk_assessment: "Datenschutz-Bewertung",
    exif_loc_found: "📍 Aufgedeckter Aufnahmeort",
    sensitive_data: "Sensible Daten",
    exif_tags_title: "Gefundene Metadaten-Tags",
    th_property: "Eigenschaft",
    th_value: "Wert",
    user_recon_title: "Einzelne Username-Suche (Sherlock)",
    user_recon_desc: "Ermittle registrierte Profile und aktive Benutzerkonten unter diesem Benutzernamen.",
    lbl_profiles_found: "Gefundene Profile:",
    btn_start_scan: "Scan starten",
    dom_title: "Domain- & Mail-Security-Audit",
    btn_scan_domain: "Domain scannen",
    pwd_check_title: "Passwort-Leak-Prüfung (k-Anonymity)",
    btn_check: "Prüfen",
    email_check_title: "E-Mail Datenpannen-Check",
    dorks_title: "Google Dorking Generator",
    btn_generate_dorks: "Abfragen generieren",
    settings_title: "⚙️ Optionale API-Keys",
    settings_desc: "Die Kernfunktionen laufen standardmäßig 100% kostenlos und ohne API-Keys. Optional können HIBP- oder Google Keys hinterlegt werden.",
    btn_back_to_cockpit: "Zum Vollscan Cockpit",
    btn_save: "Einstellungen speichern",
    classification_tag: "OSINT PRIVACY AUDIT // PERSÖNLICHES PERSONENDOSSIER",
    confidential_tag: "VERTRAULICH // NUR ZUR PRIVATEN SICHERHEITSAUDITIERUNG",
    file_ref_prefix: "AKTENZEICHEN: AZ-OSINT-2026-",
    audit_result_label: "AUDIT RESULTAT",
    risk_label_prefix: "RISIKO: ",
    link_legal_disclaimer: "⚖️ Rechtlicher Hinweis & Nutzungsbedingungen",
    modal_disclaimer_title: "Rechtlicher Hinweis, Ethische Nutzung & Haftungsausschluss",
    btn_close_disclaimer: "Verstanden & Schließen",
    tab_unsubscribe: "📬 Austragen & Opt-Out (Incogni-Style)",
    unsub_hub_title: "Mailinglisten & Werbe-Opt-Out Hub",
    unsub_hub_desc: "Trage dich automatisiert aus lästigen Mailinglisten, Verteilern und Adresshändlern aus – mit 1-Klick RFC 2369 Auto-Befehlen und rechtlich bindenden Art. 21 & Art. 17 DSGVO Widerspruchsschreiben.",
    unsub_form_title: "Ziel-Liste & Absenderdaten",
    unsub_form_subtitle: "Gib die Adresse der Mailingliste oder des Werbeabsenders ein.",
    lbl_unsub_target: "Mailingliste oder Absenderadresse",
    lbl_unsub_email: "Deine E-Mail-Adresse (die ausgetragen werden soll)",
    lbl_unsub_name: "Dein Name (Optional, für das DSGVO-Schreiben)",
    btn_gen_unsub: "1-Klick Austragungspaket generieren",
    tip_rfc_title: "So funktioniert RFC 2369 / Mailman Austragung:",
    tip_rfc_desc: "Klassische Mailinglisten (Mailman, Majordomo, Sympa) besitzen Roboter. Eine Mail mit Betreff 'unsubscribe' an <liste>-request@... meldet dich vollautomatisch ab – ohne menschliches Zutun.",
    unsub_actions_title: "1-Klick Austragungs-Aktionen",
    lbl_letter_preview: "Offizielles DSGVO Widerspruchs- & Löschschreiben (Vorausgefüllt)",
    btn_copy_letter: "Brief kopieren",
    brokers_catalog_title: "Marketing- & Adresshändler-Verzeichnis",
    brokers_catalog_sub: "Trage dich direkt bei den führenden Datenbrokern und Adresshändlern aus, die Kaltakquise und Werbelisten speisen.",
    step1_title: "1. Eingabe",
    step1_sub: "Liste oder Broker wählen",
    step2_title: "2. Info & Analyse",
    step2_sub: "Typ, DPO & Rechtsgrundlage",
    step3_title: "3. Aktion & Status",
    step3_sub: "Austragen & Protokollieren",
    unsub_step1_manual_title: "Option A: Eigene Liste oder Absender",
    unsub_step1_manual_sub: "Gib die Adresse der unerwünschten Mailingliste oder des Newsletters ein.",
    unsub_found_from_scan: "Im Scan gefundene Mailinglisten:",
    btn_use_scan_email: "Aus Vollscan übernehmen",
    btn_next_step2: "🔍 Weiter zu Schritt 2: Info & Analyse ➔",
    unsub_step1_broker_title: "Option B: Schnellauswahl Top-Datenbroker",
    unsub_step1_broker_sub: "Klicke auf einen Broker, um ihn sofort mit deinen Daten in Schritt 2 zu laden:",
    step2_header_title: "Forensische Einordnung & Rechtsgrundlage",
    btn_edit_target: "Eingabe ändern",
    card_detected_type_title: "1. Erkannter Typ & Protokoll",
    card_legal_basis_title: "2. Gesetzliche Rechtsgrundlage",
    card_routing_title: "3. Erkannte Kontaktpunkte",
    btn_back_step1: "⬅ Zurück zu Schritt 1 (Eingabe)",
    btn_next_step3: "⚡ Weiter zu Schritt 3: Aktion ausführen ➔",
    step3_header_title: "Sofort-Aktion & Status-Tracking",
    act_primary_mail_title: "1. E-Mail-Austragung",
    act_web_title: "2. Web-Opt-Out Portal",
    act_copy_title: "3. Text kopieren",
    status_tracker_title: "Incogni-Style Status-Tracker für diese Austragung:",
    btn_back_step2: "⬅ Zurück zu Schritt 2 (Info)",
    btn_new_unsub: "Weitere Liste / Weiteren Broker abmelden",
    batch_broker_title: "Alle 7 Datenbroker mit 1 Klick anschreiben",
    batch_broker_sub: "Erzeugt eine vertrauliche BCC-E-Mail an alle Datenschutzbeauftragten (Schober, microm, Acxiom, LiveRamp, Criteo, Experian, Yasni) gleichzeitig.",
    btn_batch_mailto: "1-Klick Sammel-E-Mail öffnen (BCC)",
    btn_mark_all_sent: "Alle 7 als 'Anfrage gesendet' markieren",
    btn_batch_optout_short: "Alle Datenbroker auf einmal anschreiben (1-Klick)"
  }
};

// ==================== DEFAULT GDPR TEMPLATES ====================
const defaultGdprTemplates = {
  de: `Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Löschung („Recht auf Vergessenwerden“) gemäß Art. 17 DSGVO Gebrauch.

Bitte löschen Sie unverzüglich alle personenbezogenen Daten, die zu meiner Person ([Dein Name]) gespeichert sind oder öffentlich im Index bereitgestellt werden.

Falls Sie die Daten an Dritte übermittelt haben, sind Sie nach Art. 17 Abs. 2 DSGVO verpflichtet, auch diese über mein Löschbegehren zu unterrichten.

Bitte bestätigen Sie mir die unverzügliche Löschung schriftlich.

Mit freundlichen Grüßen,
[Dein Name]`,
  en: `To Whom It May Concern,

I am writing to exercise my right to erasure ('Right to be Forgotten') pursuant to Article 17 of the General Data Protection Regulation (GDPR) / applicable privacy legislation.

Please permanently delete and erase all personal data pertaining to me ([Your Name]) stored in your databases, public directories, and web indexes without undue delay.

If you have made this personal data public or disclosed it to third parties, please inform them of this erasure request as required by law.

Please confirm the execution of this deletion in writing.

Sincerely,
[Your Name]`
};

function updateGdprLetter(targetName) {
  const gdprEl = document.getElementById('repGdprText');
  if (!gdprEl) return;
  const name = (targetName || (lastScanPayload ? lastScanPayload.name : '') || '').trim();
  const rawTemplate = defaultGdprTemplates[currentLang] || defaultGdprTemplates.en;
  if (name) {
    gdprEl.value = rawTemplate.replace(/\[(Dein Name|Your Name)\]/g, name);
  } else {
    gdprEl.value = rawTemplate;
  }
}

function updateDisclaimerContent() {
  const container = document.getElementById('disclaimerModalBody');
  if (!container) return;
  
  if (currentLang === 'de') {
    container.innerHTML = `
      <div class="space-y-3">
        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">1. Ausschließliche Zweckbestimmung (Selbstauskunft & Verteidigung)</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            Der <strong>Digital Footprint Scanner</strong> ist ausschließlich als technisches Hilfsmittel zur defensiven Selbstüberprüfung (Wahrnehmung des Auskunftsrechts gemäß <strong>Art. 15 DSGVO</strong>) sowie für autorisierte Sicherheitsaudits bestimmt. Die Nutzung zur Überwachung, Nachstellung (Stalking), Bloßstellung oder Profilerstellung dritter Personen ohne deren ausdrückliche vorherige schriftliche Einwilligung ist strikt untersagt und kann strafrechtlich verfolgt werden (u.&nbsp;a. <strong>§ 126a StGB</strong>: <em>Gefährdendes Verbreiten personenbezogener Daten</em>).
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">2. Strafrechtliche Unbedenklichkeit (§§ 202a, 202d StGB)</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            Die Software greift ausschließlich auf frei zugängliche, öffentlich erreichbare Quellen und Indizes zu. Es werden keine Zugangsschranken umgangen (kein Hacking gemäß § 202a StGB) und keine gestohlenen Datensätze gehandelt oder gespeichert (§ 202d StGB). Passwortprüfungen erfolgen strikt über den mathematischen <em>k-Anonymity-Standard</em> (Pwned Passwords), bei dem Passwörter niemals im Klartext übertragen werden.
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">3. Haftungsausschluss</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            Die Bereitstellung dieser Open-Source-Software erfolgt unter der MIT-Lizenz ohne Mängelgewähr. Die Autoren und Entwickler übernehmen keinerlei Haftung für direkte oder indirekte Schäden, rechtliche Auseinandersetzungen oder Rechtsverstöße, die durch die missbräuchliche Nutzung durch Anwender entstehen.
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">4. Keine Rechtsberatung</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            Die bereitgestellten Art. 17 DSGVO Musterschreiben und Handlungsanleitungen stellen automatisierte Entwürfe dar und ersetzen keine professionelle Rechtsberatung durch einen zugelassenen Rechtsanwalt oder Datenschutzbeauftragten.
          </p>
        </div>
      </div>
    `;
  } else {
    container.innerHTML = `
      <div class="space-y-3">
        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">1. Intended Purpose (Self-Assessment & Privacy Defense)</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            <strong>Digital Footprint Scanner</strong> is engineered exclusively for defensive personal reconnaissance (exercising the fundamental right of access pursuant to <strong>Art. 15 GDPR</strong>) and authorized security audits. Using this tool for unauthorized surveillance, stalking, harassment, doxing (§ 126a German Criminal Code - StGB), or profiling unconsenting individuals is strictly prohibited by law.
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">2. Criminal Law Compliance & Anti-Hacking Safe Harbor</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            This tool queries only public HTTP status codes, authoritative DNS records, and legitimate open OSINT APIs. No access control mechanisms or firewalls are bypassed (§ 202a StGB). No stolen databases or password dumps are downloaded, stored, or distributed (§ 202d StGB). Passwords are tested purely via cryptographic <em>k-Anonymity</em>.
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">3. Limitation of Liability</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            This software is provided "as is" under the MIT License without warranty of any kind. Under no circumstances shall the authors, maintainers, or copyright holders be held liable for damages, regulatory penalties, or legal claims resulting from improper or illegal utilization by third parties.
          </p>
        </div>

        <div class="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <h4 class="font-bold text-white text-xs mb-1">4. No Legal Advice</h4>
          <p class="text-slate-400 text-[11px] leading-relaxed">
            The provided Article 17 GDPR erasure templates and guidance are convenience templates and do not constitute formal legal counsel. For specific legal issues, consult a certified attorney or data protection officer.
          </p>
        </div>
      </div>
    `;
  }
}

function toggleDisclaimerModal(show) {
  const modal = document.getElementById('disclaimerModal');
  if (!modal) return;
  if (show) {
    updateDisclaimerContent();
    modal.classList.remove('hidden');
  } else {
    modal.classList.add('hidden');
  }
}

function setLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('selfscanner_lang', lang);

  // Update button active states
  const btnEn = document.getElementById('lang-btn-en');
  const btnDe = document.getElementById('lang-btn-de');
  if (btnEn && btnDe) {
    if (lang === 'en') {
      btnEn.className = 'px-2 py-0.5 rounded text-xs font-bold bg-indigo-600 text-white transition';
      btnDe.className = 'px-2 py-0.5 rounded text-xs font-medium text-slate-400 hover:text-white transition';
      document.documentElement.lang = 'en';
    } else {
      btnDe.className = 'px-2 py-0.5 rounded text-xs font-bold bg-indigo-600 text-white transition';
      btnEn.className = 'px-2 py-0.5 rounded text-xs font-medium text-slate-400 hover:text-white transition';
      document.documentElement.lang = 'de';
    }
  }

  // Update DOM elements with data-i18n
  const dict = translations[lang] || translations.en;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      el.textContent = dict[key];
    }
  });

  const lblLogin = document.getElementById('lblLoginBtn');
  if (lblLogin) {
    lblLogin.textContent = lang === 'de' ? 'Anmelden' : 'Sign In';
  }

  // Refresh theme button text
  if (typeof applyTheme === 'function') {
    applyTheme(currentTheme);
  }

  // Always keep GDPR letter localized
  updateGdprLetter(lastScanPayload ? lastScanPayload.name : '');
  updateDisclaimerContent();
  fetchAndRenderMarketingBrokers();

  // Re-render report if already generated
  if (lastScanResult && lastScanPayload) {
    renderFullReport(lastScanResult, lastScanPayload);
  }
}

// --- Tab Navigation ---
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
  const targetPane = document.getElementById(`tab-content-${tabId}`);
  if (targetPane) targetPane.classList.remove('hidden');

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('bg-indigo-600', 'text-white', 'shadow-md');
    btn.classList.add('text-slate-400', 'hover:text-slate-200');
  });

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.remove('text-slate-400', 'hover:text-slate-200');
    activeBtn.classList.add('bg-indigo-600', 'text-white', 'shadow-md');
  }



  if (tabId === 'scans') {
    refreshUserScans();
  }

  if (tabId === 'exif' && leafletMap) {
    setTimeout(() => leafletMap.invalidateSize(), 200);
  }

  if (tabId === 'unsubscribe') {
    // Populate user email and name from scan if empty
    if (lastScanPayload) {
      const emailInput = document.getElementById('unsubUserEmail');
      const nameInput = document.getElementById('unsubUserName');
      if (emailInput && !emailInput.value.trim() && lastScanPayload.email) emailInput.value = lastScanPayload.email;
      if (nameInput && !nameInput.value.trim() && lastScanPayload.name) nameInput.value = lastScanPayload.name;
    }
    renderFoundListsInUnsubTab();
  }
}

// ==================== 0. AUTOMATISIERTER 1-KLICK VOLLSCAN ====================
async function runFullScan(e) {
  e.preventDefault();

  const firstName = (document.getElementById('fsFirstName')?.value || '').trim();
  const lastName = (document.getElementById('fsLastName')?.value || '').trim();
  const combinedName = [firstName, lastName].filter(Boolean).join(' ');
  const legacyName = (document.getElementById('fsName')?.value || '').trim();
  const finalName = combinedName || legacyName;

  const fsNameEl = document.getElementById('fsName');
  if (fsNameEl) {
    fsNameEl.value = finalName;
  }

  const payload = {
    first_name: firstName,
    last_name: lastName,
    name: finalName,
    username: document.getElementById('fsUsername').value.trim(),
    email: document.getElementById('fsEmail').value.trim(),
    password: document.getElementById('fsPassword').value,
    city: document.getElementById('fsCity').value.trim(),
    employer: document.getElementById('fsEmployer').value.trim(),
    phone: document.getElementById('fsPhone').value.trim(),
    domain: document.getElementById('fsDomain').value.trim()
  };

  if (!payload.name && !payload.username && !payload.email && !payload.phone && !payload.domain) {
    alert(currentLang === 'de' ? 'Bitte gib mindestens einen Vor-/Nachnamen, Benutzernamen, eine E-Mail oder Domain an.' : 'Please provide at least a Name, Username, Email, or Domain.');
    return;
  }

  lastScanPayload = payload;

  const btn = document.getElementById('fsSubmitBtn');
  const btnText = document.getElementById('fsBtnText');
  const spinner = document.getElementById('fsSpinner');
  const progressBox = document.getElementById('fsProgressContainer');
  const progressBar = document.getElementById('fsProgressBar');
  const progressStep = document.getElementById('fsProgressStep');
  const reportBox = document.getElementById('fullReportContainer');

  btn.disabled = true;
  spinner.classList.remove('hidden');
  btnText.textContent = currentLang === 'de' ? 'Scanne gesamte Präsenz...' : 'Auditing digital footprint...';
  progressBox.classList.remove('hidden');
  reportBox.classList.add('hidden');

  progressBar.style.width = '30%';
  progressStep.textContent = currentLang === 'de' ? '1/3: Prüfe k-Anonymity Hashes & Identitätsvektoren...' : '1/3: Checking k-Anonymity hashes & threat vectors...';

  const t1 = setTimeout(() => {
    progressBar.style.width = '65%';
    progressStep.textContent = currentLang === 'de' ? '2/3: Durchsuche 40+ Social-Media & Tech-Plattformen...' : '2/3: Auditing 40+ platforms with bio-matching...';
  }, 900);

  const t2 = setTimeout(() => {
    progressBar.style.width = '88%';
    progressStep.textContent = currentLang === 'de' ? '3/3: Analysiere Domain-Security & erstelle DIN A4 Dossier...' : '3/3: Analyzing domain security & compiling dossier...';
  }, 1900);

  try {
    const res = await fetch('/api/scan/full', {
      method: 'POST',
      headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'include',
      body: JSON.stringify(payload)
    });
    const json = await res.json();

    clearTimeout(t1);
    clearTimeout(t2);

    if (res.status === 401) {
      alert(currentLang === 'de' 
        ? 'Zugriff verweigert: Bitte erstelle zuerst ein kostenloses Konto oder melde dich an.' 
        : 'Access denied: Please register or log in first to scan.');
      await checkAuthStatus();
      return;
    }

    if (json.success) {
      lastScanResult = json;
      progressBar.style.width = '100%';
      progressStep.textContent = currentLang === 'de' ? '✓ Vollscan abgeschlossen! DIN A4 Steckbrief erstellt.' : '✓ Full scan complete! Dossier generated.';
      setTimeout(() => progressBox.classList.add('hidden'), 800);
      renderFullReport(json, payload);

      const savedNotice = document.getElementById('scanSavedNotification');
      if (savedNotice) savedNotice.classList.remove('hidden');

      if (currentUser) {
        await refreshUserScans();
      }
    } else {
      alert('Error: ' + (json.error || 'Full scan failed'));
    }
  } catch (err) {
    clearTimeout(t1);
    clearTimeout(t2);
    alert('Error during full scan: ' + err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add('hidden');
    btnText.textContent = translations[currentLang].btn_start_fullscan;
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

let currentWebDirectories = [];
let activeWebDirCategory = 'all';

function renderWebDirectories(dirs = []) {
  currentWebDirectories = dirs;
  activeWebDirCategory = 'all';
  const searchInput = document.getElementById('webDirSearchInput');
  if (searchInput) searchInput.value = '';

  // Extract unique categories
  const categories = ['all'];
  dirs.forEach(d => {
    if (d.category && !categories.includes(d.category)) {
      categories.push(d.category);
    }
  });

  const pillsContainer = document.getElementById('webDirCategoryPills');
  if (pillsContainer) {
    pillsContainer.innerHTML = categories.map(cat => {
      const isAll = cat === 'all';
      const label = isAll ? (currentLang === 'de' ? 'Alle' : 'All') : cat;
      const count = isAll ? dirs.length : dirs.filter(d => d.category === cat).length;
      return `
        <button type="button" onclick="setWebDirCategory('${cat}')" id="pill-webdir-${cat.replace(/\s+/g, '-')}" 
          class="webdir-pill px-2 py-0.5 rounded-md text-[10px] font-semibold transition cursor-pointer flex items-center space-x-1 ${isAll ? 'bg-indigo-600 text-white shadow-sm' : 'bg-slate-900 border border-slate-700 text-slate-400 hover:text-white'}">
          <span>${label}</span>
          <span class="text-[9px] opacity-75 font-mono">(${count})</span>
        </button>
      `;
    }).join('');
  }

  filterWebDirectories();
}

function setWebDirCategory(cat) {
  activeWebDirCategory = cat;
  document.querySelectorAll('.webdir-pill').forEach(btn => {
    btn.className = 'webdir-pill px-2 py-0.5 rounded-md text-[10px] font-semibold transition cursor-pointer flex items-center space-x-1 bg-slate-900 border border-slate-700 text-slate-400 hover:text-white';
  });
  const activeBtn = document.getElementById(`pill-webdir-${cat.replace(/\s+/g, '-')}`);
  if (activeBtn) {
    activeBtn.className = 'webdir-pill px-2 py-0.5 rounded-md text-[10px] font-semibold transition cursor-pointer flex items-center space-x-1 bg-indigo-600 text-white shadow-sm';
  }
  filterWebDirectories();
}

function getWebDirCategoryBadge(cat) {
  const c = (cat || '').toLowerCase();
  if (c.includes('suchmaschinen') || c.includes('search')) {
    return 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/50';
  } else if (c.includes('beruf') || c.includes('karriere') || c.includes('business')) {
    return 'bg-blue-950/60 text-blue-300 border border-blue-800/50';
  } else if (c.includes('handelsregister') || c.includes('wirtschaft')) {
    return 'bg-amber-950/60 text-amber-300 border border-amber-800/50';
  } else if (c.includes('amtlich') || c.includes('bekanntmachung')) {
    return 'bg-orange-950/60 text-orange-300 border border-orange-800/50';
  } else if (c.includes('telefon') || c.includes('adresse')) {
    return 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/50';
  } else if (c.includes('person') || c.includes('profil')) {
    return 'bg-yellow-950/60 text-yellow-300 border border-yellow-800/50';
  } else if (c.includes('presse') || c.includes('medien')) {
    return 'bg-purple-950/60 text-purple-300 border border-purple-800/50';
  }
  return 'bg-slate-900 text-slate-400 border border-slate-800';
}

function filterWebDirectories() {
  const container = document.getElementById('sbWebDirectoriesList');
  const countBadge = document.getElementById('sbWebDirsFilterCount');
  if (!container) return;

  const searchInput = document.getElementById('webDirSearchInput');
  const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

  const filtered = currentWebDirectories.filter(d => {
    const matchCat = activeWebDirCategory === 'all' || d.category === activeWebDirCategory;
    if (!matchCat) return false;
    if (!query) return true;
    const haystack = `${d.site} ${d.category} ${d.desc} ${d.query || ''}`.toLowerCase();
    return haystack.includes(query);
  });

  if (countBadge) {
    countBadge.textContent = currentLang === 'de' 
      ? `${filtered.length} von ${currentWebDirectories.length} Einträgen`
      : `${filtered.length} of ${currentWebDirectories.length} entries`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <tr>
        <td colspan="5" class="py-4 text-center text-slate-500 font-mono text-[11px]">
          ${currentLang === 'de' ? 'Keine Webseiten für diesen Filter gefunden.' : 'No websites match this filter.'}
        </td>
      </tr>
    `;
    return;
  }

  container.innerHTML = filtered.map(d => {
    const badgeClass = getWebDirCategoryBadge(d.category);
    const linkText = currentLang === 'de' ? 'Öffnen ↗' : 'Open ↗';
    const queryDisplay = d.query 
      ? `<span class="text-indigo-300 font-mono text-[10px] bg-indigo-950/40 px-1 py-0.5 rounded border border-indigo-900/40" title="${escapeHtml(d.query)}">${escapeHtml(d.query)}</span>` 
      : '<span class="text-slate-600">-</span>';

    return `
      <tr class="hover:bg-slate-900/60 transition">
        <td class="py-2 px-3 font-bold text-white flex items-center space-x-1.5 whitespace-nowrap">
          <span>${d.icon || '🌐'}</span>
          <span>${escapeHtml(d.site)}</span>
        </td>
        <td class="py-2 px-3 whitespace-nowrap">
          <span class="px-1.5 py-0.5 rounded text-[10px] font-sans font-medium ${badgeClass}">
            ${escapeHtml(d.category)}
          </span>
        </td>
        <td class="py-2 px-3 max-w-[200px] truncate" title="${escapeHtml(d.query || '')}">
          ${queryDisplay}
        </td>
        <td class="py-2 px-3 text-slate-300 max-w-xs truncate text-[11px] font-sans" title="${escapeHtml(d.desc)}">
          ${escapeHtml(d.desc)}
        </td>
        <td class="py-2 px-3 text-right whitespace-nowrap">
          <a href="${escapeHtml(d.url)}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline font-semibold text-[11px]">
            ${linkText}
          </a>
        </td>
      </tr>
    `;
  }).join('');
}

// ==================== VISUELLE MEDIATHEK & BILD-WOLKE ====================
let currentMediaImages = [];

function renderMediaCloud(images = []) {
  currentMediaImages = images;
  const cloudContainer = document.getElementById('sbMediaCloudContainer');
  const countBadge = document.getElementById('sbMediaCloudCountBadge');
  const sourcesAccordion = document.getElementById('sbMediaSourcesAccordion');
  const sourcesContent = document.getElementById('sbMediaSourcesContent');
  const sourcesTotalBadge = document.getElementById('sbMediaSourcesTotalBadge');
  
  if (!cloudContainer) return;

  const totalSources = images.reduce((acc, img) => acc + (img.sources ? img.sources.length : 0), 0);

  if (countBadge) {
    countBadge.textContent = currentLang === 'de'
      ? `${images.length} ${images.length === 1 ? 'Bild' : 'Bilder'} (${totalSources} Quellen)`
      : `${images.length} ${images.length === 1 ? 'Image' : 'Images'} (${totalSources} Sources)`;
  }
  if (sourcesTotalBadge) {
    sourcesTotalBadge.textContent = currentLang === 'de'
      ? `${totalSources} Fundstellen`
      : `${totalSources} Sources`;
  }

  if (images.length === 0) {
    cloudContainer.innerHTML = `
      <div class="p-6 text-center text-slate-500 font-mono text-xs space-y-1 w-full">
        <span class="text-2xl block">🛡️</span>
        <div class="text-slate-300 font-bold">${currentLang === 'de' ? 'Keine öffentlichen Profilbilder im Web gefunden' : 'No public profile photos indexed'}</div>
        <div class="text-slate-500 text-[11px]">${currentLang === 'de' ? 'Hervorragender Schutz deiner visuellen Identität: Auf den geprüften Diensten wurden keine öffentlich zugänglichen Avatare hinterlegt.' : 'High visual privacy: No public avatars or photos were discovered on scanned platforms.'}</div>
      </div>
    `;
    if (sourcesAccordion) sourcesAccordion.classList.add('hidden');
    return;
  }

  if (sourcesAccordion) sourcesAccordion.classList.remove('hidden');

  // Render the Word-Cloud of images (larger if count is higher)
  cloudContainer.innerHTML = images.map((img, idx) => {
    const cnt = img.count || 1;
    let sizeClasses = 'w-20 h-20 sm:w-24 sm:h-24 md:w-28 md:h-28 rounded-xl ring-1 ring-slate-700 shadow-md';
    let badgeHtml = `<span class="absolute -top-1.5 -right-1.5 px-1.5 py-0.2 rounded-full text-[8px] font-semibold bg-slate-800 text-slate-300 border border-slate-600 shadow">1x</span>`;
    let glowEffect = '';

    if (img.size_tier === 'xl' || cnt >= 3) {
      sizeClasses = 'w-36 h-36 sm:w-44 sm:h-44 md:w-52 md:h-52 rounded-2xl ring-4 ring-indigo-500/80 shadow-2xl shadow-indigo-500/25';
      badgeHtml = `
        <span class="absolute -top-2.5 -right-2 px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-indigo-600 text-white shadow-lg border border-indigo-400 flex items-center space-x-1 animate-pulse">
          <span>🔥</span>
          <span>${cnt}x ${currentLang === 'de' ? 'gefunden' : 'found'}</span>
        </span>
      `;
      glowEffect = 'scale-105';
    } else if (img.size_tier === 'lg' || cnt === 2) {
      sizeClasses = 'w-28 h-28 sm:w-32 sm:h-32 md:w-36 md:h-36 rounded-2xl ring-2 ring-cyan-500/70 shadow-xl shadow-cyan-500/20';
      badgeHtml = `
        <span class="absolute -top-2 -right-2 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider bg-cyan-700 text-white shadow-md border border-cyan-400">
          ${cnt}x ${currentLang === 'de' ? 'gefunden' : 'found'}
        </span>
      `;
    }

    const sourcesSummary = (img.sources || []).map(s => s.platform).join(', ');

    return `
      <div class="relative group cursor-pointer transition-transform duration-300 hover:scale-105 hover:z-20 ${glowEffect}" onclick="openMediaLightbox(${idx})">
        <div class="${sizeClasses} overflow-hidden bg-slate-900 flex items-center justify-center relative">
          <img src="${escapeHtml(img.url)}" alt="Gefundenes Foto" class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110" onerror="this.closest('.group').style.display='none'">
          <div class="absolute inset-0 bg-gradient-to-t from-slate-950/90 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity p-2.5 flex flex-col justify-end">
            <span class="text-[11px] font-bold text-white leading-tight truncate">${escapeHtml(sourcesSummary)}</span>
            <span class="text-[9px] text-indigo-300 font-mono mt-0.5">${currentLang === 'de' ? 'Klicken für Details ↗' : 'Click for details ↗'}</span>
          </div>
        </div>
        ${badgeHtml}
      </div>
    `;
  }).join('');

  // Render the expandable sources list underneath
  if (sourcesContent) {
    sourcesContent.innerHTML = images.map((img, idx) => {
      const cnt = img.count || 1;
      const badgeClass = cnt >= 3 
        ? 'bg-indigo-950 text-indigo-300 border-indigo-800' 
        : (cnt === 2 ? 'bg-cyan-950 text-cyan-300 border-cyan-800' : 'bg-slate-900 text-slate-400 border-slate-800');

      return `
        <div class="p-3 bg-slate-900/60 rounded-xl border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition">
          <div class="flex items-start sm:items-center space-x-3 flex-1 min-w-0">
            <img src="${escapeHtml(img.url)}" onclick="openMediaLightbox(${idx})" class="w-12 h-12 rounded-lg object-cover border border-slate-700 shrink-0 cursor-pointer hover:opacity-80 transition" onerror="this.style.display='none'" />
            <div class="flex-1 min-w-0 space-y-1">
              <div class="flex items-center space-x-2">
                <span class="text-xs font-bold text-white">Bild #${idx + 1}</span>
                <span class="text-[10px] px-2 py-0.5 rounded-full border ${badgeClass} font-mono font-bold">
                  ${cnt}x ${currentLang === 'de' ? 'im Web verwendet' : 'used online'}
                </span>
              </div>
              <div class="flex flex-wrap items-center gap-1.5 pt-0.5">
                ${(img.sources || []).map(s => `
                  <a href="${escapeHtml(s.url)}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-[11px] text-slate-300 hover:text-white transition group/link">
                    <span class="font-bold text-indigo-400">${escapeHtml(s.platform)}:</span>
                    <span class="truncate max-w-[180px] text-slate-400">${escapeHtml(s.title || s.url)}</span>
                    <span class="text-[9px] text-slate-500 group-hover/link:text-indigo-300">↗</span>
                  </a>
                `).join('')}
              </div>
            </div>
          </div>
          <div class="flex items-center space-x-1.5 shrink-0 self-end sm:self-center">
            <a href="${escapeHtml(img.google_lens_url)}" target="_blank" rel="noopener noreferrer" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[10px] font-semibold border border-slate-700 transition">
              Google Lens ↗
            </a>
            <a href="${escapeHtml(img.url)}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-[10px] font-bold transition">
              ${currentLang === 'de' ? 'Bild öffnen' : 'Open Image'} ↗
            </a>
          </div>
        </div>
      `;
    }).join('');
  }
}

function toggleMediaSources() {
  const content = document.getElementById('sbMediaSourcesContent');
  const chevron = document.getElementById('sbMediaSourcesChevron');
  if (!content) return;
  const isHidden = content.classList.contains('hidden');
  if (isHidden) {
    content.classList.remove('hidden');
    if (chevron) chevron.textContent = '▲';
  } else {
    content.classList.add('hidden');
    if (chevron) chevron.textContent = '▼';
  }
}

function toggleSubdomains() {
  const content = document.getElementById('sbSubdomainsContent');
  const chevron = document.getElementById('sbSubdomainsChevron');
  if (!content) return;
  const isHidden = content.classList.contains('hidden');
  if (isHidden) {
    content.classList.remove('hidden');
    if (chevron) chevron.textContent = '▲';
  } else {
    content.classList.add('hidden');
    if (chevron) chevron.textContent = '▼';
  }
}

function renderInfraProjects(infra) {
  const section = document.getElementById('sbInfraSection');
  if (!section) return;

  if (!infra || !infra.checked || (!infra.cohosted_domains || infra.cohosted_domains.length === 0)) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  const ipBadge = document.getElementById('sbInfraIpBadge');
  const countBadge = document.getElementById('sbInfraCountBadge');
  if (ipBadge) ipBadge.textContent = `Server-IP: ${infra.server_ip}`;
  if (countBadge) {
    const total = infra.cohosted_domains.length;
    countBadge.textContent = currentLang === 'de' 
      ? `${total} ${total === 1 ? 'Web-Projekt' : 'Web-Projekte'}`
      : `${total} ${total === 1 ? 'project' : 'projects'}`;
  }

  const tbody = document.getElementById('sbInfraTableBody');
  if (tbody) {
    tbody.innerHTML = '';
    infra.cohosted_domains.forEach(d => {
      const tr = document.createElement('tr');
      const isOnline = d.online;
      const statusBadge = isOnline
        ? `<span class="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">🟢 ${d.status} OK</span>`
        : `<span class="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px]">${d.status ? `⚠️ ${d.status}` : '⚪ Offline'}</span>`;

      tr.innerHTML = `
        <td class="py-2 px-3 font-bold text-white flex items-center space-x-1.5">
          <span>🌐</span>
          <span>${d.domain}</span>
        </td>
        <td class="py-2 px-3">${statusBadge}</td>
        <td class="py-2 px-3 text-slate-300 italic max-w-sm truncate" title="${d.title || ''}">${d.title || '-'}</td>
        <td class="py-2 px-3 text-right">
          <a href="${d.url}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline font-semibold">${currentLang === 'de' ? 'Öffnen ↗' : 'Visit ↗'}</a>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Subdomains Accordion
  const subAccordion = document.getElementById('sbSubdomainsAccordion');
  const subContent = document.getElementById('sbSubdomainsContent');
  const subBadge = document.getElementById('sbSubdomainsTotalBadge');
  if (subAccordion && subContent) {
    const subs = infra.subdomains || [];
    if (subs.length > 0) {
      subAccordion.classList.remove('hidden');
      if (subBadge) {
        subBadge.textContent = currentLang === 'de' ? `${subs.length} Subdomains` : `${subs.length} subdomains`;
      }
      subContent.innerHTML = subs.map(s => `
        <a href="https://${s}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-indigo-500 font-mono text-[11px] transition">
          ${s} ↗
        </a>
      `).join('');
    } else {
      subAccordion.classList.add('hidden');
    }
  }
}

function renderLiveWebResults(results) {
  const section = document.getElementById('sbLiveWebSection');
  if (!section) return;

  if (!results || results.length === 0) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  const badge = document.getElementById('sbLiveWebCountBadge');
  if (badge) {
    badge.textContent = currentLang === 'de'
      ? `${results.length} ${results.length === 1 ? 'bestätigte Fundstelle' : 'bestätigte Fundstellen'}`
      : `${results.length} ${results.length === 1 ? 'verified hit' : 'verified hits'}`;
  }

  const tbody = document.getElementById('sbLiveWebTableBody');
  if (tbody) {
    tbody.innerHTML = '';
    results.forEach(item => {
      const tr = document.createElement('tr');
      const sigs = (item.matched_signals || []).map(s => 
        `<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-mono">✓ ${escapeHtml(s)}</span>`
      ).join(' ');

      tr.innerHTML = `
        <td class="py-2.5 px-3 font-bold text-white max-w-xs truncate" title="${escapeHtml(item.title)}">
          <div class="flex items-center space-x-1.5">
            <span>🌐</span>
            <span>${escapeHtml(item.title)}</span>
          </div>
          <span class="text-[10px] text-slate-400 font-normal block font-mono truncate">${escapeHtml(item.url)}</span>
        </td>
        <td class="py-2.5 px-3 whitespace-nowrap">
          <div class="flex flex-wrap gap-1">${sigs || '<span class="text-slate-400">-</span>'}</div>
        </td>
        <td class="py-2.5 px-3 text-slate-300 italic max-w-sm truncate" title="${escapeHtml(item.snippet)}">${escapeHtml(item.snippet)}</td>
        <td class="py-2.5 px-3 text-right whitespace-nowrap">
          <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline font-semibold">${currentLang === 'de' ? 'Webseite ↗' : 'Visit ↗'}</a>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
}

function openMediaLightbox(index) {
  const img = currentMediaImages[index];
  if (!img) return;
  const modal = document.getElementById('mediaLightboxModal');
  const lbImg = document.getElementById('lightboxImg');
  const lbTitle = document.getElementById('lightboxTitle');
  const lbSources = document.getElementById('lightboxSources');
  const lbLens = document.getElementById('lightboxGoogleLens');
  const lbTinEye = document.getElementById('lightboxTinEye');
  const lbYandex = document.getElementById('lightboxYandex');
  const lbDirect = document.getElementById('lightboxDirect');

  if (lbImg) lbImg.src = img.url;
  if (lbTitle) {
    lbTitle.textContent = currentLang === 'de'
      ? `Gefundenes Foto (Auf ${img.count || 1} Plattformen identifiziert)`
      : `Discovered Photo (Identified on ${img.count || 1} platforms)`;
  }
  if (lbSources) {
    lbSources.innerHTML = (img.sources || []).map(s => `
      <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
        <strong class="text-indigo-400">${escapeHtml(s.platform)}</strong>: ${escapeHtml(s.title || s.url)}
      </span>
    `).join('');
  }
  if (lbLens) lbLens.href = img.google_lens_url;
  if (lbTinEye) lbTinEye.href = img.tineye_url;
  if (lbYandex) lbYandex.href = img.yandex_url;
  if (lbDirect) lbDirect.href = img.url;

  if (modal) modal.classList.remove('hidden');
}

function closeMediaLightbox() {
  const modal = document.getElementById('mediaLightboxModal');
  if (modal) modal.classList.add('hidden');
}

function renderFullReport(res, payload) {
  const data = res;
  const s = data.summary;
  fullScanProfiles = data.found_profiles || [];
  const t = translations[currentLang] || translations.en;

  const reportContainer = document.getElementById('fullReportContainer');
  reportContainer.classList.remove('hidden');

  // Set Timestamp & Dossier Az
  const now = new Date();
  const dateStr = currentLang === 'de' ? now.toLocaleDateString('de-DE') : now.toLocaleDateString('en-US');
  const timeStr = currentLang === 'de' ? now.toLocaleTimeString('de-DE') : now.toLocaleTimeString('en-US');
  document.getElementById('dossierTimestamp').textContent = `${currentLang === 'de' ? 'Erstellt am' : 'Generated'}: ${dateStr} ${timeStr}`;
  
  const randNum = Math.floor(1000 + Math.random() * 9000);
  document.getElementById('dossierAktenzeichen').textContent = `${t.file_ref_prefix}${randNum}`;
  document.getElementById('dossierClassification').textContent = t.classification_tag;
  document.getElementById('dossierConfidentialTag').textContent = t.confidential_tag;

  // 1. Steckbrief-Kopf
  const resolvedHandle = data.resolved_username || data.discovered_handle;
  const resolvedCity = data.resolved_city || (data.summary && data.summary.discovered_location);
  const resolvedName = data.resolved_name;

  const targetName = payload.name || resolvedName || (resolvedHandle ? `@${resolvedHandle}` : (currentLang === 'de' ? 'UNBEKANNTE ZIELPERSON' : 'UNKNOWN TARGET'));
  document.getElementById('sbTargetNameTop').textContent = targetName;
  
  const compactName = document.getElementById('compactTargetName');
  if (compactName) compactName.textContent = targetName;

  if (payload.username) {
    document.getElementById('sbTargetAliasTop').textContent = `@${payload.username}`;
    const compactAlias = document.getElementById('compactTargetAlias');
    if (compactAlias) compactAlias.textContent = `@${payload.username}`;
  } else if (resolvedHandle) {
    document.getElementById('sbTargetAliasTop').innerHTML = `<span class="text-indigo-400 font-bold">@${resolvedHandle}</span> <span class="text-[10px] text-slate-400">(via OSINT)</span>`;
    const compactAlias = document.getElementById('compactTargetAlias');
    if (compactAlias) compactAlias.textContent = `@${resolvedHandle}`;
  } else {
    document.getElementById('sbTargetAliasTop').textContent = payload.name ? `${payload.name}` : '-';
    const compactAlias = document.getElementById('compactTargetAlias');
    if (compactAlias) compactAlias.textContent = payload.name || '-';
  }

  // Feature 3: Avatar- & Foto-Forensik (Reverse Image OSINT)
  const avatarPlaceholder = document.getElementById('sbAvatarPlaceholder');
  const avatarImg = document.getElementById('sbAvatarImg');
  const revSection = document.getElementById('sbReverseImageSection');
  if (data.avatar_url) {
    if (avatarImg) {
      avatarImg.src = data.avatar_url;
      avatarImg.classList.remove('hidden');
    }
    if (avatarPlaceholder) avatarPlaceholder.classList.add('hidden');
    if (revSection) {
      revSection.classList.remove('hidden');
      const encUrl = encodeURIComponent(data.avatar_url);
      const btnLens = document.getElementById('btnLens');
      const btnTinEye = document.getElementById('btnTinEye');
      const btnYandex = document.getElementById('btnYandex');
      if (btnLens) btnLens.href = `https://lens.google.com/uploadbyurl?url=${encUrl}`;
      if (btnTinEye) btnTinEye.href = `https://tineye.com/search?url=${encUrl}`;
      if (btnYandex) btnYandex.href = `https://yandex.com/images/search?rpt=imageview&url=${encUrl}`;
    }
  } else {
    if (avatarImg) avatarImg.classList.add('hidden');
    if (avatarPlaceholder) avatarPlaceholder.classList.remove('hidden');
    if (revSection) revSection.classList.add('hidden');
  }

  // Stammdaten-Tabelle
  document.getElementById('sbName').textContent = payload.name || resolvedName || '-';
  document.getElementById('sbCity').textContent = payload.city || (resolvedCity ? `${resolvedCity} (via Gravatar)` : '-');
  document.getElementById('sbEmployer').textContent = payload.employer || '-';
  document.getElementById('sbEmail').textContent = payload.email || '-';
  
  if (data.phone_result) {
    document.getElementById('sbPhone').textContent = `${data.phone_result.raw} (${data.phone_result.type} - ${data.phone_result.region_or_carrier})`;
  } else {
    document.getElementById('sbPhone').textContent = payload.phone || '-';
  }
  document.getElementById('sbDomain').textContent = payload.domain || '-';

  // Exposure Stamp
  document.getElementById('sbExposureVal').textContent = `${s.exposure_score}%`;
  
  let riskTranslated = s.exposure_level;
  if (currentLang === 'en') {
    const map = { 'KRITISCH': 'CRITICAL', 'HOCH': 'HIGH', 'MODERAT': 'MODERATE', 'GERING': 'LOW' };
    riskTranslated = map[s.exposure_level] || s.exposure_level;
  }
  document.getElementById('sbExposureLevel').textContent = `${t.risk_label_prefix}${riskTranslated}`;
  
  const stamp = document.getElementById('sbDossierStamp');
  if (s.exposure_score >= 70) {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-rose-500 text-rose-500';
  } else if (s.exposure_score >= 35) {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-amber-500 text-amber-500';
  } else {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-emerald-500 text-emerald-500';
  }

  const compactRiskStamp = document.getElementById('compactRiskStamp');
  if (compactRiskStamp) {
    compactRiskStamp.textContent = `EXPOSURE: ${s.exposure_score}% (${riskTranslated})`;
    compactRiskStamp.className = `px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-${s.badge_color || 'emerald'}-400 font-bold`;
  }

  // 2. Sicherheitsstatus (Section 1)
  const pwdStatus = document.getElementById('sbPwdStatus');
  const pwdDetail = document.getElementById('sbPwdDetail');
  if (s.password_pwned === true) {
    pwdStatus.innerHTML = `<span class="text-rose-400">⚠️ ${s.password_breach_count.toLocaleString()}x ${currentLang === 'de' ? 'GELEAKT!' : 'LEAKED!'}</span>`;
    pwdDetail.textContent = currentLang === 'de' ? 'Passwort ist öffentlich kompromittiert!' : 'Password compromised in known breaches!';
  } else if (s.password_pwned === false) {
    pwdStatus.innerHTML = `<span class="text-emerald-400">✓ ${currentLang === 'de' ? 'Sicher (Kein Leak)' : 'Safe (No breach)'}</span>`;
    pwdDetail.textContent = currentLang === 'de' ? 'In 800M+ Datensätzen sauber' : 'Clean in 800M+ leaked records';
  } else {
    pwdStatus.textContent = currentLang === 'de' ? 'Nicht getestet' : 'Not tested';
    pwdDetail.textContent = currentLang === 'de' ? 'Kein Passwort übermittelt' : 'No password provided';
  }

  const emailStatus = document.getElementById('sbEmailStatus');
  const emailDetail = document.getElementById('sbEmailDetail');
  if (data.email_result) {
    if (data.email_result.breached) {
      emailStatus.innerHTML = `<span class="text-rose-400">⚠️ ${currentLang === 'de' ? `In ${data.email_result.breach_count} Datenlecks` : `In ${data.email_result.breach_count} data breaches`}</span>`;
      const names = (data.email_result.breach_names || []).slice(0, 3).join(', ');
      emailDetail.textContent = names ? `${names}...` : (currentLang === 'de' ? 'Betroffen von Sicherheitsvorfällen' : 'Affected by data leaks');
    } else {
      emailStatus.innerHTML = `<span class="text-emerald-400">✓ ${currentLang === 'de' ? 'Keine direkten Leaks' : 'No direct breaches'}</span>`;
      emailDetail.textContent = currentLang === 'de' ? 'Keine Treffer in Standard-Indizes' : 'Clean across breach directories';
    }
  } else {
    emailStatus.textContent = payload.email ? (currentLang === 'de' ? 'Geprüft' : 'Audited') : (currentLang === 'de' ? 'Keine E-Mail angegeben' : 'No email provided');
    emailDetail.textContent = payload.email ? 'k-Anonymity / OSINT' : '-';
  }

  const stealerStatus = document.getElementById('sbInfostealerStatus');
  const stealerDetail = document.getElementById('sbInfostealerDetail');
  if (stealerStatus && stealerDetail) {
    if (data.infostealer_result && data.infostealer_result.checked) {
      if (data.infostealer_result.infected) {
        stealerStatus.innerHTML = `<span class="text-rose-400">⚠️ ${data.infostealer_result.stealers_count}x ${currentLang === 'de' ? 'INFIZIERT' : 'INFECTED'}</span>`;
        const fams = (data.infostealer_result.families || []).join(', ');
        stealerDetail.textContent = fams ? `Trojaner: ${fams}` : (currentLang === 'de' ? 'Passwörter durch Malware erbeutet' : 'Credentials leaked via stealer trojans');
      } else {
        stealerStatus.innerHTML = `<span class="text-emerald-400">✓ ${currentLang === 'de' ? 'Sauber (0 Infektionen)' : 'Clean (0 Infections)'}</span>`;
        stealerDetail.textContent = currentLang === 'de' ? 'Kein Befall durch RedLine/Vidar' : 'Clean in cybercrime stealer DB';
      }
    } else {
      stealerStatus.textContent = payload.email ? (currentLang === 'de' ? 'Geprüft' : 'Audited') : (currentLang === 'de' ? 'Keine E-Mail' : 'No email');
      stealerDetail.textContent = 'Hudson Rock Cybercrime DB';
    }
  }

  const domStatus = document.getElementById('sbDomainStatus');
  const domDetail = document.getElementById('sbDomainDetail');
  if (data.domain_result) {
    const spf = data.domain_result.email_security.spf.status;
    const dmarc = data.domain_result.email_security.dmarc.status;
    if (spf === 'secure' && dmarc === 'secure') {
      domStatus.innerHTML = `<span class="text-emerald-400">✓ ${currentLang === 'de' ? 'Gesichert' : 'Secure'}</span>`;
      domDetail.textContent = currentLang === 'de' ? 'Strikter SPF- und DMARC-Schutz' : 'Strict SPF & DMARC protection';
    } else {
      domStatus.innerHTML = `<span class="text-amber-400">⚠️ ${currentLang === 'de' ? `Schwachstelle (${spf})` : `Vulnerable (${spf})`}</span>`;
      domDetail.textContent = data.domain_result.email_security.dmarc.assessment;
    }
  } else {
    domStatus.textContent = currentLang === 'de' ? 'Keine Domain' : 'No domain';
    domDetail.textContent = currentLang === 'de' ? 'Nicht analysiert' : 'Not analyzed';
  }

  // 3. Webseiten & Profile (Section 2)
  const webDirs = data.web_directories || [];
  const verifiedCount = s.high_confidence_matches || 0;

  document.getElementById('sbProfilesCountText').textContent = currentLang === 'de' 
    ? `${fullScanProfiles.length} ${fullScanProfiles.length === 1 ? 'bestätigter Account' : 'bestätigte Accounts'}`
    : `${fullScanProfiles.length} ${fullScanProfiles.length === 1 ? 'verified account' : 'verified accounts'}`;

  const tbody = document.getElementById('sbProfilesTableBody');
  tbody.innerHTML = '';

  if (fullScanProfiles.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500 font-mono text-xs">${currentLang === 'de' ? 'Keine öffentlichen Accounts unter diesem Benutzernamen / Namen gefunden (Ausgezeichneter digitaler Datenschutz).' : 'No public accounts identified for this username / name (High digital privacy).'}</td></tr>`;
  } else {
    fullScanProfiles.forEach(p => {
      const isHigh = p.match && (p.match.confidence === 'high' || p.match.confidence === 'medium');
      let matchBadge = `<span class="px-2 py-0.5 text-[10px] rounded bg-slate-900 text-slate-400 border border-slate-800">⚪ ${currentLang === 'de' ? 'Account existiert (Identität unbestätigt)' : 'Account exists (Unverified)'}</span>`;
      if (p.match && p.match.confidence === 'high') {
        matchBadge = `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-800">🟢 ${currentLang === 'de' ? 'Bestätigt durch Bio / Daten' : 'Verified by Bio / Metadata'}</span>`;
      } else if (p.match && p.match.confidence === 'medium') {
        matchBadge = `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-yellow-950 text-yellow-400 border border-yellow-800">🟡 ${currentLang === 'de' ? 'Kontext-Übereinstimmung' : 'Context Match'}</span>`;
      }

      const noteText = p.snippet ? `"${p.snippet}"` : (p.match && p.match.matches && p.match.matches.length > 0 ? p.match.matches.join(', ') : '-');
      const linkLabel = p.category === 'Eigene Web-Präsenz' ? (currentLang === 'de' ? 'Webseite ↗' : 'Website ↗') : (currentLang === 'de' ? 'Profil ↗' : 'Profile ↗');

      const tr = document.createElement('tr');
      tr.className = isHigh ? 'bg-indigo-950/20' : '';
      tr.innerHTML = `
        <td class="py-2 px-3 font-bold text-white flex items-center space-x-1.5">
          <span>${p.category === 'Eigene Web-Präsenz' ? '🌐' : '👤'}</span>
          <span>${p.platform}</span>
        </td>
        <td class="py-2 px-3 text-slate-400">${p.category}</td>
        <td class="py-2 px-3">${matchBadge}</td>
        <td class="py-2 px-3 text-slate-300 italic max-w-xs truncate">${noteText}</td>
        <td class="py-2 px-3 text-right">
          <a href="${p.url}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline font-semibold">${linkLabel}</a>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 3. Visuelle Mediathek & Bild-Wolke (Word-Cloud skaliert mit Häufigkeit)
  renderMediaCloud(data.discovered_images || []);

  // 3b. Server-Infrastruktur & Verbundene Web-Projekte (Co-Hosted Domains & Subdomains)
  renderInfraProjects(data.infra_result);

  // 3c. Verifizierte Web-Fundstellen (Suchmaschinen-Index mit Namensvetter-Filter)
  renderLiveWebResults(data.live_web_results);

  // 4. Bedrohungsvektoren (Section 3 - Strictly verified facts)
  const threatsBox = document.getElementById('sbThreatsContainer');
  threatsBox.innerHTML = '';
  const threats = data.identity_audit.threat_vectors || [];
  if (threats.length === 0) {
    threatsBox.innerHTML = `<p class="text-emerald-400 text-xs font-medium">✓ ${currentLang === 'de' ? 'Keine verifizierten Sicherheitsvorfälle, Leaks oder Konfigurationsfehler festgestellt (Alle durchgeführten Prüfungen negativ).' : 'No verified security breaches, leaked passwords, or DNS vulnerabilities detected across checked records.'}</p>`;
  } else {
    threats.forEach(tv => {
      const title = currentLang === 'de' ? tv.title : (tv.title_en || tv.title);
      const desc = currentLang === 'de' ? tv.desc : (tv.desc_en || tv.desc);
      const div = document.createElement('div');
      div.className = 'p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-3';
      div.innerHTML = `
        <div>
          <span class="font-bold text-white block text-xs">${title}</span>
          <span class="text-slate-400 text-[11px] leading-relaxed block mt-0.5">${desc}</span>
        </div>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-400 border border-rose-800 shrink-0">${tv.severity}</span>
      `;
      threatsBox.appendChild(div);
    });
  }

  // 5. Phone & Mailing Lists & Verified Email (Section 4)
  const phoneBox = document.getElementById('sbPhoneReconBox');
  if (data.phone_result) {
    const pr = data.phone_result;
    phoneBox.innerHTML = `
      <div class="mb-1 text-white font-mono font-bold">${pr.raw} &rarr; ${pr.type} (${pr.region_or_carrier})</div>
      <div class="flex flex-wrap gap-1.5 pt-1">
        ${pr.lookup_links.map(l => `<a href="${l.url}" target="_blank" class="text-[10px] text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 hover:underline">${l.name} ↗</a>`).join('')}
      </div>
    `;
  } else {
    phoneBox.textContent = currentLang === 'de' ? 'Keine Rufnummer angegeben.' : 'No phone number provided.';
  }

  const mlBox = document.getElementById('sbMailingListBox');
  if (data.mailing_list_result) {
    const ml = data.mailing_list_result;
    const foundLists = ml.found_lists || [];
    if (foundLists.length > 0) {
      mlBox.innerHTML = `
        <div class="text-emerald-400 font-bold mb-1.5 flex items-center justify-between text-xs">
          <span>📬 ${currentLang === 'de' ? `${foundLists.length} Mailinglisten gefunden` : `${foundLists.length} mailing lists found`}:</span>
        </div>
        <div class="space-y-1.5 max-h-48 overflow-y-auto pr-1">
          ${foundLists.map(l => {
            const listId = l.identifier || l.name;
            return `
              <div class="p-2 rounded bg-slate-900 border border-indigo-950 flex items-center justify-between gap-2">
                <div class="truncate">
                  <div class="font-mono text-white text-[11px] font-semibold truncate">${l.name}</div>
                  <div class="text-[9px] text-slate-400 font-mono truncate">${listId}</div>
                </div>
                <button onclick="openUnsubscribeForEmail('${listId}')" class="shrink-0 px-2 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-[10px] font-bold cursor-pointer transition flex items-center space-x-1 shadow">
                  <span>⚡</span>
                  <span>${currentLang === 'de' ? 'Austragen ➔' : 'Opt-out ➔'}</span>
                </button>
              </div>
            `;
          }).join('')}
        </div>
        <button onclick="openUnsubscribeForEmail()" class="mt-2.5 w-full py-1.5 px-2 bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-700 rounded-lg text-[10px] font-semibold transition flex items-center justify-center space-x-1 cursor-pointer">
          <span>📬 ${currentLang === 'de' ? 'Alle Verteiler im Opt-Out Hub verwalten ↗' : 'Manage all lists in Opt-Out Hub ↗'}</span>
        </button>
      `;
    } else {
      mlBox.innerHTML = `
        <div class="text-slate-300 font-medium mb-1 flex items-center space-x-1">
          <span class="text-emerald-400">✓</span>
          <span>${currentLang === 'de' ? '0 öffentliche Mailinglisten-Einträge' : '0 public mailing list entries found'}</span>
        </div>
        <div class="text-[10px] text-slate-400 mb-2">
          ${currentLang === 'de' ? 'Keine Erwähnungen in öffentlichen Diskussions- und Software-Archiven.' : 'No posts indexed in public discussion archives.'}
        </div>
        <button onclick="openUnsubscribeForEmail()" class="mt-1 w-full py-1.5 px-2 bg-slate-900 hover:bg-slate-800 text-indigo-300 border border-slate-700 rounded-lg text-[10px] font-semibold transition flex items-center justify-center space-x-1 cursor-pointer">
          <span>✉️ ${currentLang === 'de' ? 'Manuelle Liste/Newsletter austragen ↗' : 'Unsubscribe manual list/newsletter ↗'}</span>
        </button>
      `;
    }
  } else {
    mlBox.textContent = currentLang === 'de' ? 'Keine E-Mail angegeben.' : 'No email provided.';
  }

  const emailAuditBox = document.getElementById('sbEmailAuditBox');
  if (emailAuditBox) {
    if (payload.email) {
      const ml = data.mailing_list_result || {};
      const er = data.email_result || {};
      const ea = data.email_accounts || [];
      const mxText = ml.has_valid_mx
        ? `<span class="text-emerald-400">✓ DNS MX erreichbar (${ml.mx_hosts ? ml.mx_hosts[0] : 'OK'})</span>`
        : `<span class="text-slate-400">-</span>`;
      
      const breachText = er.breached
        ? `<span class="text-rose-400 font-bold">⚠️ ${currentLang === 'de' ? `In ${er.breach_count} Datenpannen` : `In ${er.breach_count} leaks`}</span>`
        : `<span class="text-emerald-400 font-medium">✓ ${currentLang === 'de' ? '0 bekannte Datenlecks' : '0 known leaks'}</span>`;

      let regAccountsHtml = '';
      if (ea.length > 0) {
        regAccountsHtml = `<div class="mt-2 pt-2 border-t border-slate-800 space-y-1"><span class="text-[10px] uppercase font-bold text-indigo-400 block">${currentLang === 'de' ? 'Verifizierte Konten:' : 'Verified Accounts:'}</span>` +
          ea.map(a => `<div class="text-[11px] text-slate-300 flex items-center justify-between"><span>• <strong class="text-white">${a.service}</strong></span><span class="text-[10px] text-emerald-400 font-mono">${a.status || 'Aktiv'}</span></div>`).join('') +
          `</div>`;
      }

      emailAuditBox.innerHTML = `
        <div class="text-white font-mono font-bold truncate">${payload.email}</div>
        <div class="text-[11px] text-slate-300 mt-1 space-y-1">
          <div>Leak-Status: ${breachText}</div>
          <div>Routing: ${mxText}</div>
          ${regAccountsHtml}
        </div>
      `;
    } else {
      emailAuditBox.textContent = currentLang === 'de' ? 'Keine E-Mail angegeben.' : 'No email provided.';
    }
  }

  // 6. Register & Dorks (Section 5)
  const dorksBox = document.getElementById('sbDorksLinksList');
  dorksBox.innerHTML = '';
  (data.dorks || []).forEach(cat => {
    cat.items.forEach(item => {
      const a = document.createElement('a');
      a.href = item.google_url;
      a.target = '_blank';
      a.className = 'px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-indigo-400 hover:text-indigo-300 hover:border-indigo-500 transition text-[11px] flex items-center space-x-1';
      a.innerHTML = `<span>🔍 ${item.title}</span> <span>↗</span>`;
      dorksBox.appendChild(a);
    });
  });

  // 7. Remediation & Cleanup Plan (FootprintIQ Inspired)
  const cleanupBox = document.getElementById('sbCleanupGuidesList');
  cleanupBox.innerHTML = '';
  const rem = data.remediation_guide || { account_guides: [], data_brokers: [] };
  
  if (rem.account_guides.length === 0) {
    cleanupBox.innerHTML = `<div class="col-span-2 text-slate-500 text-[11px]">${currentLang === 'de' ? 'Keine spezifischen Löschleitfäden für diese Accounts hinterlegt.' : 'No direct deactivation guides found for these specific accounts.'}</div>`;
  } else {
    rem.account_guides.forEach(g => {
      const instr = currentLang === 'de' ? g.instructions_de : g.instructions;
      const c = document.createElement('div');
      c.className = 'p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-start justify-between gap-3';
      c.innerHTML = `
        <div>
          <span class="font-bold text-white text-xs block">${g.platform} - ${currentLang === 'de' ? 'Konto löschen' : 'Delete Account'}</span>
          <span class="text-[11px] text-slate-400 block mt-0.5 leading-relaxed">${instr}</span>
        </div>
        <a href="${g.delete_url}" target="_blank" class="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-[11px] font-medium shrink-0 transition">
          ${currentLang === 'de' ? 'Löschen ↗' : 'Delete ↗'}
        </a>
      `;
      cleanupBox.appendChild(c);
    });
  }

  // Data Brokers Opt-Out
  const brokerBox = document.getElementById('sbDataBrokersList');
  brokerBox.innerHTML = '';
  if (rem.data_brokers.length === 0) {
    brokerBox.innerHTML = `<div class="col-span-2 text-slate-500 text-[11px]">${currentLang === 'de' ? 'Kein Name zur Personensuchmaschinen-Abfrage angegeben.' : 'No full name provided for data broker check.'}</div>`;
  } else {
    rem.data_brokers.forEach(b => {
      const descText = currentLang === 'de' ? b.desc_de : b.desc;
      const d = document.createElement('div');
      d.className = 'p-2.5 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between gap-2';
      d.innerHTML = `
        <div class="truncate">
          <span class="font-bold text-slate-200 block truncate">${b.name}</span>
          <span class="text-[10px] text-slate-500 block truncate">${descText}</span>
        </div>
        <div class="flex items-center space-x-1.5 shrink-0">
          <a href="${b.search_url}" target="_blank" class="text-[10px] text-cyan-400 hover:underline">${currentLang === 'de' ? 'Eintrag prüfen ↗' : 'Check entry ↗'}</a>
          <span class="text-slate-600">|</span>
          <a href="${b.opt_out_url}" target="_blank" class="text-[10px] text-rose-400 hover:underline font-semibold">${currentLang === 'de' ? 'Austragen ↗' : 'Opt-Out ↗'}</a>
        </div>
      `;
      brokerBox.appendChild(d);
    });
  }

  // 8. GDPR Letter
  updateGdprLetter(payload.name);

  // Scroll smoothly down to the dossier
  reportContainer.scrollIntoView({ behavior: 'smooth' });
}

let isCompactDossier = false;

function toggleDossierView() {
  const dossier = document.getElementById('dossierSheet');
  const btnText = document.getElementById('toggleViewText');
  const btnIcon = document.getElementById('toggleViewIcon');
  const badge = document.getElementById('activeModeBadge');
  if (!dossier) return;

  isCompactDossier = !isCompactDossier;

  if (isCompactDossier) {
    dossier.classList.add('compact-mode');
    if (btnText) btnText.textContent = currentLang === 'de' ? 'Dossier-Modus (Vollansicht)' : 'Dossier View (Full)';
    if (btnIcon) btnIcon.textContent = '📄';
    if (badge) {
      badge.textContent = currentLang === 'de' ? '🗜️ Kompakt-Modus (Aktiv)' : '🗜️ Compact View (Active)';
      badge.className = 'ml-2 text-[10px] font-mono uppercase font-bold px-2.5 py-1 rounded-md bg-emerald-950 text-emerald-400 border border-emerald-800 shadow-sm';
    }
  } else {
    dossier.classList.remove('compact-mode');
    if (btnText) btnText.textContent = currentLang === 'de' ? 'Kompakt-Modus' : 'Compact View';
    if (btnIcon) btnIcon.textContent = '🗜️';
    if (badge) {
      badge.textContent = currentLang === 'de' ? '📄 Dossier-Modus (DIN A4)' : '📄 Dossier Mode (DIN A4)';
      badge.className = 'ml-2 text-[10px] font-mono uppercase font-bold px-2.5 py-1 rounded-md bg-indigo-950 text-indigo-400 border border-indigo-800 shadow-sm';
    }
  }
}

// Copy GDPR helper
function copyGdprTemplate(btn) {
  const text = document.getElementById('repGdprText') ? document.getElementById('repGdprText').value : '';
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = currentLang === 'de' ? '✓ Kopiert!' : '✓ Copied!';
    setTimeout(() => btn.textContent = orig, 1800);
  });
}

// ==================== 1. USERNAME SCANNER (INDIVIDUAL TAB) ====================
function startUsernameScan(e) {
  e.preventDefault();
  const username = document.getElementById('usernameInput').value.trim();
  if (!username) return;

  if (usernameEventSource) usernameEventSource.close();

  currentResults = [];
  document.getElementById('usernameResultsGrid').innerHTML = '';
  document.getElementById('usernameProgressSection').classList.remove('hidden');
  document.getElementById('scanFoundCount').textContent = '0';
  const statusText = document.getElementById('scanStatusText');
  if (statusText) statusText.textContent = currentLang === 'de' ? 'Prüfung läuft...' : 'Scanning in progress...';

  const btn = document.getElementById('usernameScanBtn');
  btn.disabled = true;
  btn.textContent = currentLang === 'de' ? 'Scanne...' : 'Scanning...';

  const url = `/api/scan/username/stream?username=${encodeURIComponent(username)}`;
  usernameEventSource = new EventSource(url);

  usernameEventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.event === 'done') {
      btn.disabled = false;
      btn.textContent = translations[currentLang].btn_start_scan;
      if (statusText) statusText.textContent = currentLang === 'de' ? 'Abgeschlossen' : 'Completed';
      document.getElementById('scanProgressBar').style.width = '100%';
      usernameEventSource.close();

      const grid = document.getElementById('usernameResultsGrid');
      if (currentResults.length === 0) {
        grid.innerHTML = `
          <div class="col-span-full p-8 bg-slate-900 border border-slate-800 rounded-2xl text-center text-slate-400 text-xs shadow-inner">
            <span class="text-2xl block mb-2">🔍</span>
            <span class="font-bold text-slate-300 block mb-1">${currentLang === 'de' ? 'Keine Accounts gefunden' : 'No accounts found'}</span>
            <span>${currentLang === 'de' ? 'Unter diesem Benutzernamen wurden keine aktiven Benutzerkonten identifiziert.' : 'No active accounts were identified under this handle.'}</span>
          </div>
        `;
      }
      return;
    }

    if (data.progress) {
      document.getElementById('scanProgressBar').style.width = `${data.progress.percent}%`;
      document.getElementById('scanFoundCount').textContent = data.progress.found;
      if (statusText) statusText.textContent = `${data.progress.percent}%`;
    }

    if (data.exists) {
      currentResults.push(data);
      const card = document.createElement('div');
      card.className = 'p-3.5 bg-slate-900 rounded-xl border border-emerald-500/50 flex justify-between items-center shadow-sm';
      card.innerHTML = `
        <div>
          <span class="font-bold text-white text-xs block">${data.platform}</span>
          <span class="text-[10px] text-slate-400">${data.category}</span>
        </div>
        <a href="${data.url}" target="_blank" class="text-xs text-cyan-400 hover:underline font-semibold">${currentLang === 'de' ? 'Profil öffnen ↗' : 'Open profile ↗'}</a>
      `;
      document.getElementById('usernameResultsGrid').appendChild(card);
    }
  };

  usernameEventSource.onerror = function() {
    btn.disabled = false;
    btn.textContent = translations[currentLang].btn_start_scan;
    if (usernameEventSource) usernameEventSource.close();
  };
}

// ==================== 2. EXIF INSPECTOR ====================
const dropZone = document.getElementById('dropZone');
if (dropZone) {
  dropZone.addEventListener('click', () => document.getElementById('exifFileInput').click());
  ['dragenter', 'dragover'].forEach(ev => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('border-cyan-400'); }));
  ['dragleave', 'drop'].forEach(ev => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('border-cyan-400'); }));
  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFileSelect(files[0]);
  });
}

async function handleFileSelect(file) {
  if (!file) return;
  currentSelectedFile = file;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/exif/inspect', { method: 'POST', body: formData });
    const json = await res.json();
    if (json.success) renderExifResults(json.data);
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

function renderExifResults(data) {
  document.getElementById('exifActions').classList.remove('hidden');
  document.getElementById('exifRiskCard').classList.remove('hidden');
  document.getElementById('exifTableContainer').classList.remove('hidden');

  const badge = document.getElementById('exifRiskBadge');
  badge.textContent = `${currentLang === 'de' ? 'Risiko' : 'Risk'}: ${data.risk_level}`;
  badge.className = 'text-xs px-2.5 py-1 rounded font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800';

  const reasons = document.getElementById('exifRiskReasons');
  reasons.innerHTML = data.risk_reasons.map(r => `<li>• ${r}</li>`).join('');

  const tbody = document.getElementById('exifTableBody');
  tbody.innerHTML = Object.entries(data.metadata).map(([k, v]) => `<tr><td class="py-2 px-3 font-semibold text-slate-400">${k}</td><td class="py-2 px-3 text-slate-200 break-all">${v}</td></tr>`).join('');

  const mapContainer = document.getElementById('exifMapContainer');
  if (data.gps) {
    mapContainer.classList.remove('hidden');
    document.getElementById('exifMapCoords').textContent = `${data.gps.latitude}, ${data.gps.longitude}`;
    if (!leafletMap) {
      leafletMap = L.map('exifMap').setView([data.gps.latitude, data.gps.longitude], 15);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(leafletMap);
      leafletMarker = L.marker([data.gps.latitude, data.gps.longitude]).addTo(leafletMap);
    } else {
      leafletMap.setView([data.gps.latitude, data.gps.longitude], 15);
      leafletMarker.setLatLng([data.gps.latitude, data.gps.longitude]);
    }
  }
}

async function downloadSanitizedImage() {
  if (!currentSelectedFile) return;
  const formData = new FormData();
  formData.append('file', currentSelectedFile);
  const res = await fetch('/api/exif/strip', { method: 'POST', body: formData });
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = window.URL.createObjectURL(blob);
  a.download = `sanitized_${currentSelectedFile.name}`;
  a.click();
}

// ==================== 3. DOMAIN RECON ====================
async function startDomainRecon(e) {
  e.preventDefault();
  const domain = document.getElementById('domainInput').value.trim();
  const res = await fetch(`/api/recon/domain?domain=${encodeURIComponent(domain)}`);
  const json = await res.json();
  if (json.success) {
    document.getElementById('domainResults').classList.remove('hidden');
    const spf = json.data.email_security.spf;
    const dmarc = json.data.email_security.dmarc;
    document.getElementById('spfBadge').textContent = spf.status;
    document.getElementById('spfAssessment').textContent = spf.assessment;
    document.getElementById('dmarcBadge').textContent = dmarc.status;
    document.getElementById('dmarcAssessment').textContent = dmarc.assessment;
  }
}

// ==================== 4. BREACH CHECK ====================
async function checkPassword(e) {
  e.preventDefault();
  const pwd = document.getElementById('passwordInput').value;
  const res = await fetch('/api/breach/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pwd })
  });
  const json = await res.json();
  const r = document.getElementById('pwdResult');
  r.classList.remove('hidden');
  if (json.data.pwned) {
    r.className = 'mt-4 p-4 rounded-xl border bg-rose-950 text-rose-300';
    r.innerHTML = `⚠️ ${currentLang === 'de' ? `Gefunden in ${json.data.count.toLocaleString()} Leaks!` : `Found in ${json.data.count.toLocaleString()} breaches!`}`;
  } else {
    r.className = 'mt-4 p-4 rounded-xl border bg-emerald-950 text-emerald-300';
    r.innerHTML = `✓ ${currentLang === 'de' ? 'Kein Leak gefunden.' : 'No breach found.'}`;
  }
}

async function checkEmail(e) {
  e.preventDefault();
  const email = document.getElementById('emailInput').value.trim();
  const res = await fetch(`/api/breach/email?email=${encodeURIComponent(email)}`);
  const json = await res.json();
  const r = document.getElementById('emailResult');
  r.classList.remove('hidden');
  r.innerHTML = `<div class="p-3 bg-slate-950 rounded border border-slate-800 text-xs">${json.data.message || (currentLang === 'de' ? 'Geprüft' : 'Audited')}</div>`;
}

// ==================== 5. DORKS ====================
async function generateDorkQueries(e) {
  e.preventDefault();
  const res = await fetch('/api/dorks/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('dorkName').value,
      city: document.getElementById('dorkCity').value
    })
  });
  const json = await res.json();
  const c = document.getElementById('dorksContainer');
  c.innerHTML = json.data.map(cat => `
    <div class="p-4 bg-slate-900 rounded-xl border border-slate-800">
      <h3 class="font-bold text-sm text-white mb-2">${cat.category}</h3>
      ${cat.items.map(i => `<div class="text-xs py-1"><a href="${i.google_url}" target="_blank" class="text-indigo-400 hover:underline">${i.title} ↗</a></div>`).join('')}
    </div>
  `).join('');
}



// ==================== 7. UNSUBSCRIBE & OPT-OUT HUB (INCOGNI-STYLE GUIDED FLOW) ====================
let currentUnsubStep = 1;
let currentUnsubData = null;
let cachedMarketingBrokers = null;
let removalStatusStore = JSON.parse(localStorage.getItem('selfscanner_unsub_statuses') || '{}');

function openUnsubscribeForEmail(targetList = null) {
  if (lastScanPayload) {
    const emailInput = document.getElementById('unsubUserEmail');
    const nameInput = document.getElementById('unsubUserName');
    if (emailInput && lastScanPayload.email) emailInput.value = lastScanPayload.email;
    if (nameInput && lastScanPayload.name) nameInput.value = lastScanPayload.name;
  }

  const targetInput = document.getElementById('unsubTargetInput');
  if (targetList) {
    // Only pre-fill if explicitly passed and not the user's own domain
    const userDomain = (lastScanPayload && lastScanPayload.email && lastScanPayload.email.includes('@'))
      ? lastScanPayload.email.split('@')[1].toLowerCase()
      : '';
    const targetDomain = (targetList.includes('@')) ? targetList.split('@')[1].toLowerCase() : '';
    if (!userDomain || userDomain !== targetDomain) {
      if (targetInput) targetInput.value = targetList;
    }
  }

  switchTab('unsubscribe');
  goToUnsubStep(1);
  renderFoundListsInUnsubTab();

  // If a valid target input and email are pre-filled, advance to Step 2
  if (targetInput && targetInput.value.trim() && lastScanPayload && lastScanPayload.email) {
    handleStep1Submit(null, 2);
  } else if (targetInput) {
    targetInput.focus();
  }
}

function renderFoundListsInUnsubTab() {
  const box = document.getElementById('unsubFoundListsBox');
  const pills = document.getElementById('unsubFoundListsPills');
  if (!box || !pills) return;

  const foundLists = (lastScanResult && lastScanResult.mailing_list_result && lastScanResult.mailing_list_result.found_lists)
    ? lastScanResult.mailing_list_result.found_lists
    : [];

  if (foundLists.length > 0) {
    box.classList.remove('hidden');
    pills.innerHTML = foundLists.map(l => {
      const targetVal = l.identifier || l.name;
      return `
        <button type="button" onclick="selectFoundListQuick('${targetVal}')" class="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-indigo-900 border border-indigo-700 hover:border-indigo-500 text-white font-mono text-xs flex items-center space-x-1.5 transition cursor-pointer shadow-sm">
          <span>📬</span>
          <span class="font-bold">${l.name}</span>
          <span class="text-[10px] text-indigo-300">(${targetVal})</span>
          <span class="text-[10px] text-emerald-400 font-sans font-semibold">➔ Ausfüllen</span>
        </button>
      `;
    }).join('');
  } else {
    box.classList.add('hidden');
    pills.innerHTML = '';
  }
}

function selectFoundListQuick(targetList) {
  const targetInput = document.getElementById('unsubTargetInput');
  const userEmailInput = document.getElementById('unsubUserEmail');
  const userNameInput = document.getElementById('unsubUserName');

  if (targetInput) targetInput.value = targetList;
  if (userEmailInput && (!userEmailInput.value || !userEmailInput.value.trim()) && lastScanPayload && lastScanPayload.email) {
    userEmailInput.value = lastScanPayload.email;
  }
  if (userNameInput && (!userNameInput.value || !userNameInput.value.trim()) && lastScanPayload && lastScanPayload.name) {
    userNameInput.value = lastScanPayload.name;
  }

  if (userEmailInput && userEmailInput.value.trim()) {
    handleStep1Submit(null, 2);
  } else {
    alert(currentLang === 'de' ? `Mailingliste "${targetList}" im Feld eingefügt. Bitte gib noch deine E-Mail an.` : `Mailing list "${targetList}" filled. Please provide your email.`);
    if (userEmailInput) userEmailInput.focus();
  }
}

function populateUserEmailFromScan() {
  if (lastScanPayload && lastScanPayload.email) {
    const emailInput = document.getElementById('unsubUserEmail');
    const nameInput = document.getElementById('unsubUserName');
    if (emailInput) emailInput.value = lastScanPayload.email;
    if (nameInput && lastScanPayload.name) nameInput.value = lastScanPayload.name;
  } else {
    alert(currentLang === 'de' ? 'Im letzten Scan war keine E-Mail hinterlegt.' : 'No email was provided in the last scan.');
  }
}

function goToUnsubStep(stepNum) {
  // If navigating to step 2 or 3 without data, check if we can generate it
  if ((stepNum === 2 || stepNum === 3) && !currentUnsubData) {
    const targetInput = document.getElementById('unsubTargetInput');
    const userEmailInput = document.getElementById('unsubUserEmail');
    if (targetInput && userEmailInput && targetInput.value.trim() && userEmailInput.value.trim()) {
      handleStep1Submit(null, stepNum);
      return;
    } else {
      stepNum = 1;
    }
  }

  currentUnsubStep = stepNum;

  // Toggle pane visibility
  ['unsubStep1', 'unsubStep2', 'unsubStep3'].forEach((id, idx) => {
    const pane = document.getElementById(id);
    if (pane) {
      if (idx + 1 === stepNum) {
        pane.classList.remove('hidden');
      } else {
        pane.classList.add('hidden');
      }
    }
  });

  // Update step navigation tabs styling
  for (let s = 1; s <= 3; s++) {
    const tabBtn = document.getElementById(`unsub-step-tab-${s}`);
    const badge = document.getElementById(`unsub-step-badge-${s}`);
    if (!tabBtn || !badge) continue;

    if (s === stepNum) {
      tabBtn.className = 'p-3 rounded-xl border transition flex items-center space-x-3 bg-indigo-950/80 border-indigo-500 text-white cursor-pointer';
      badge.className = 'w-7 h-7 rounded-full bg-indigo-600 text-white font-bold flex items-center justify-center text-xs shrink-0';
      badge.textContent = `${s}`;
    } else if (s < stepNum || (currentUnsubData && s <= 2)) {
      tabBtn.className = 'p-3 rounded-xl border transition flex items-center space-x-3 bg-slate-900 border-slate-700 text-slate-200 hover:border-slate-600 cursor-pointer';
      badge.className = 'w-7 h-7 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold flex items-center justify-center text-xs shrink-0';
      badge.textContent = '✓';
    } else {
      tabBtn.className = 'p-3 rounded-xl border transition flex items-center space-x-3 bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 cursor-pointer';
      badge.className = 'w-7 h-7 rounded-full bg-slate-800 text-slate-300 font-bold flex items-center justify-center text-xs shrink-0';
      badge.textContent = `${s}`;
    }
  }
}

async function handleStep1Submit(e, targetStep = 2) {
  if (e) e.preventDefault();

  const targetInput = document.getElementById('unsubTargetInput');
  const userEmailInput = document.getElementById('unsubUserEmail');
  const userNameInput = document.getElementById('unsubUserName');
  const submitBtn = document.getElementById('btnToStep2');

  const listIdentifier = targetInput.value.trim();
  const userEmail = userEmailInput.value.trim();
  const userName = userNameInput.value.trim();

  if (!listIdentifier || !userEmail) {
    alert(currentLang === 'de' ? 'Bitte Mailingliste/Absender und deine E-Mail angeben.' : 'Please enter the list/sender and your email.');
    if (targetInput && !listIdentifier) targetInput.focus();
    else if (userEmailInput && !userEmail) userEmailInput.focus();
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add('opacity-75');
  }

  try {
    const res = await fetch('/api/unsubscribe/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        list_identifier: listIdentifier,
        user_email: userEmail,
        user_name: userName,
        lang: currentLang
      })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentUnsubData = json.data;
      renderUnsubSteps(currentUnsubData);
      goToUnsubStep(targetStep);
    } else {
      alert(json.error || (currentLang === 'de' ? 'Fehler bei der Analyse des Verteilers.' : 'Failed to analyze list target.'));
    }
  } catch (err) {
    console.error('Failed to generate unsubscribe analysis:', err);
    alert(currentLang === 'de' ? 'Fehler bei der Analyse des Verteilers.' : 'Failed to analyze list target.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.classList.remove('opacity-75');
    }
  }
}

function renderUnsubSteps(d) {
  // Step 2: Info fields
  const sub2 = document.getElementById('step2TargetSubtitle');
  if (sub2) sub2.textContent = `${d.target} • (${d.user_email})`;

  const detType = document.getElementById('infoDetectedType');
  if (detType) detType.textContent = currentLang === 'de' ? d.detected_category_de : d.detected_category_en;

  const protSum = document.getElementById('infoProtocolSummary');
  if (protSum) protSum.textContent = currentLang === 'de' ? d.protocol_summary_de : d.protocol_summary_en;

  const legSum = document.getElementById('infoLegalSummary');
  if (legSum) legSum.textContent = currentLang === 'de' ? d.legal_summary_de : d.legal_summary_en;

  const tgtAddr = document.getElementById('infoTargetAddress');
  if (tgtAddr) tgtAddr.textContent = d.target;

  const primCont = document.getElementById('infoPrimaryContact');
  if (primCont) primCont.textContent = d.mailman_request_email || d.primary_contact || `privacy@${(d.target.split('@')[1] || d.target)}`;

  // Step 3: Action fields
  const sub3 = document.getElementById('step3TargetSubtitle');
  if (sub3) sub3.textContent = `${d.target} • (${d.user_email})`;

  // Primary Mailto Link (RFC command preferred if mailman, else GDPR objection)
  const btnMail = document.getElementById('btnPrimaryMailto');
  const mailDesc = document.getElementById('actMailDesc');
  const mailUrl = d.rfc_mailto || d.gdpr_mailto;
  if (btnMail && mailUrl) {
    btnMail.href = mailUrl;
    btnMail.classList.remove('pointer-events-none', 'opacity-50');
  }

  // Webmail alternatives for Step 3
  const btnGmail = document.getElementById('btnPrimaryGmail');
  if (btnGmail) {
    if (d.gmail_url) {
      btnGmail.href = d.gmail_url;
      btnGmail.classList.remove('hidden');
    } else {
      btnGmail.classList.add('hidden');
    }
  }

  const btnOutlook = document.getElementById('btnPrimaryOutlook');
  if (btnOutlook) {
    if (d.outlook_url) {
      btnOutlook.href = d.outlook_url;
      btnOutlook.classList.remove('hidden');
    } else {
      btnOutlook.classList.add('hidden');
    }
  }
  if (mailDesc) {
    if (d.detected_type === 'rfc_list') {
      mailDesc.textContent = currentLang === 'de'
        ? `Sendet den Roboterbefehl 'unsubscribe' an ${d.mailman_request_email} für automatische De-Registrierung.`
        : `Sends automated daemon command 'unsubscribe' to ${d.mailman_request_email}.`;
    } else {
      mailDesc.textContent = currentLang === 'de'
        ? `Öffnet rechtlich bindenden Art. 21 DSGVO Werbewiderspruch an ${d.target}.`
        : `Opens statutory Art. 21 GDPR direct marketing objection to ${d.target}.`;
    }
  }

  // Web Portal Link
  const btnWeb = document.getElementById('btnPrimaryWebPortal');
  if (btnWeb) {
    if (d.web_options_url) {
      btnWeb.href = d.web_options_url;
      btnWeb.classList.remove('pointer-events-none', 'opacity-50');
    } else {
      btnWeb.href = '#';
      btnWeb.classList.add('pointer-events-none', 'opacity-50');
    }
  }

  // Letter Preview Textarea
  const letterArea = document.getElementById('unsubLetterText');
  if (letterArea) letterArea.value = d.gdpr_body;

  // Restore removal status for this target
  const savedStatus = removalStatusStore[d.target] || 'pending';
  updateRemovalStatusUI(savedStatus);
}

function selectBrokerQuick(brokerName, privacyEmail, optOutUrl) {
  const targetInput = document.getElementById('unsubTargetInput');
  const userEmailInput = document.getElementById('unsubUserEmail');
  const userNameInput = document.getElementById('unsubUserName');

  if (targetInput) targetInput.value = privacyEmail || brokerName;
  if (userEmailInput && !userEmailInput.value.trim() && lastScanPayload && lastScanPayload.email) {
    userEmailInput.value = lastScanPayload.email;
  }
  if (userNameInput && !userNameInput.value.trim() && lastScanPayload && lastScanPayload.name) {
    userNameInput.value = lastScanPayload.name;
  }

  if (userEmailInput && userEmailInput.value.trim()) {
    handleStep1Submit(null, 2);
  } else {
    alert(currentLang === 'de' ? `Broker "${brokerName}" ausgewählt. Bitte gib noch deine E-Mail an.` : `Broker "${brokerName}" selected. Please provide your email.`);
    if (userEmailInput) userEmailInput.focus();
  }
}

function setRemovalStatus(status) {
  if (!currentUnsubData || !currentUnsubData.target) return;
  removalStatusStore[currentUnsubData.target] = status;
  localStorage.setItem('selfscanner_unsub_statuses', JSON.stringify(removalStatusStore));
  updateRemovalStatusUI(status);
}

function updateRemovalStatusUI(status) {
  const badge = document.getElementById('trackerCurrentBadge');
  const note = document.getElementById('trackerStatusNote');
  const btnPending = document.getElementById('btnStatusPending');
  const btnSent = document.getElementById('btnStatusSent');
  const btnCompleted = document.getElementById('btnStatusCompleted');

  // Reset button classes
  [btnPending, btnSent, btnCompleted].forEach(b => {
    if (b) {
      b.className = 'py-2 px-3 rounded-lg border text-xs font-semibold transition bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700 cursor-pointer';
    }
  });

  if (status === 'completed') {
    if (badge) {
      badge.textContent = currentLang === 'de' ? '✅ Erfolgreich abgemeldet' : '✅ Unsubscribed & Erased';
      badge.className = 'text-xs px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono font-bold';
    }
    if (note) {
      note.textContent = currentLang === 'de' ? 'Austragung erfolgreich vollzogen und bestätigt.' : 'Successfully unsubscribed and erased from list.';
    }
    if (btnCompleted) {
      btnCompleted.className = 'py-2 px-3 rounded-lg border text-xs font-semibold transition bg-emerald-950 text-emerald-300 border-emerald-700 font-bold';
    }
  } else if (status === 'sent') {
    if (badge) {
      badge.textContent = currentLang === 'de' ? '📨 Anfrage gesendet' : '📨 Request Dispatched';
      badge.className = 'text-xs px-2.5 py-1 rounded bg-amber-950 text-amber-400 border border-amber-800 font-mono font-bold';
    }
    if (note) {
      note.textContent = currentLang === 'de' ? 'Anfrage versendet. Gesetzliche Frist zur Löschung gem. Art. 12 Abs. 3 DSGVO: 1 Monat.' : 'Request sent. Legal deadline for deletion under Art. 12(3) GDPR: 1 month.';
    }
    if (btnSent) {
      btnSent.className = 'py-2 px-3 rounded-lg border text-xs font-semibold transition bg-amber-950 text-amber-300 border-amber-700 font-bold';
    }
  } else {
    if (badge) {
      badge.textContent = currentLang === 'de' ? '⏳ Nicht gesendet' : '⏳ Pending / Not Sent';
      badge.className = 'text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono font-bold';
    }
    if (note) {
      note.textContent = currentLang === 'de' ? 'Noch keine Austragung versendet.' : 'No removal request dispatched yet.';
    }
    if (btnPending) {
      btnPending.className = 'py-2 px-3 rounded-lg border text-xs font-semibold transition bg-slate-800 text-slate-200 border-slate-600 font-bold';
    }
  }
}

function resetUnsubWizard() {
  const targetInput = document.getElementById('unsubTargetInput');
  if (targetInput) targetInput.value = '';
  currentUnsubData = null;
  goToUnsubStep(1);
}

function copyUnsubLetter() {
  const letterArea = document.getElementById('unsubLetterText');
  if (!letterArea || !letterArea.value) return;

  navigator.clipboard.writeText(letterArea.value).then(() => {
    const btn = document.getElementById('btnCopyLetterStep3');
    const orig = btn ? btn.textContent : '';
    if (btn) btn.textContent = currentLang === 'de' ? '✓ Kopiert!' : '✓ Copied!';
    setTimeout(() => {
      if (btn) btn.textContent = orig;
    }, 2000);
  });
}

let cachedBatchData = null;

function triggerMailto(url) {
  const a = document.createElement('a');
  a.href = url;
  a.target = '_top';
  a.rel = 'noopener noreferrer';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => a.remove(), 100);
}

async function ensureBatchData() {
  const userEmailInput = document.getElementById('unsubUserEmail');
  const userNameInput = document.getElementById('unsubUserName');

  let email = (userEmailInput ? userEmailInput.value.trim() : '') || (lastScanPayload ? lastScanPayload.email : '');
  let name = (userNameInput ? userNameInput.value.trim() : '') || (lastScanPayload ? lastScanPayload.name : '');
  let phone = lastScanPayload ? (lastScanPayload.phone || '') : '';
  let city = lastScanPayload ? (lastScanPayload.city || '') : '';

  if (!email) {
    alert(currentLang === 'de' 
      ? 'Bitte trage zuerst deine E-Mail-Adresse ein, die bei den Brokern gelöscht werden soll.' 
      : 'Please enter your email address that should be deleted across all brokers.');
    if (userEmailInput) userEmailInput.focus();
    return null;
  }

  try {
    const res = await fetch('/api/unsubscribe/batch-brokers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_email: email,
        user_name: name,
        user_phone: phone,
        user_city: city,
        lang: currentLang
      })
    });
    const json = await res.json();
    if (json.success && json.data) {
      cachedBatchData = json.data;
      return cachedBatchData;
    }
  } catch (err) {
    console.error('Failed to generate batch broker data:', err);
  }
  return null;
}

async function dispatchBatchBrokerOptOut() {
  const data = await ensureBatchData();
  if (!data) return;

  triggerMailto(data.batch_mailto);
  markAllBrokersSent(false);

  alert(currentLang === 'de' 
    ? `✓ Sammel-E-Mail an ${data.brokers_count} Datenschutzbeauftragte (BCC) im Mailprogramm aufgerufen!\n(Falls sich auf deinem Mac kein Programm öffnet: Klicke einfach auf '🔴 In Gmail öffnen' oder '📋 Empfänger & Text kopieren')` 
    : `✓ Multi-broker email with ${data.brokers_count} DPOs (BCC) launched in mail client!\n(If it does not open on Mac, use the '🔴 Open in Gmail' button)`);
}

async function dispatchBatchBrokerWebmail(provider) {
  const data = await ensureBatchData();
  if (!data) return;

  if (provider === 'gmail' && data.gmail_url) {
    window.open(data.gmail_url, '_blank');
  } else if (provider === 'outlook' && data.outlook_url) {
    window.open(data.outlook_url, '_blank');
  }
  markAllBrokersSent(false);
}

async function copyBatchBrokerDetails() {
  const data = await ensureBatchData();
  if (!data) return;

  const textToCopy = `AN (To): ${data.primary_to}\nBCC: ${data.bcc_emails.join(', ')}\n\nBETREFF: ${data.subject}\n\nTEXT:\n${data.body}`;
  navigator.clipboard.writeText(textToCopy).then(() => {
    const btn = document.getElementById('btnCopyBatchBroker');
    const orig = btn ? btn.innerHTML : '';
    if (btn) btn.innerHTML = `<span>✓</span><span>Kopiert!</span>`;
    setTimeout(() => {
      if (btn) btn.innerHTML = orig;
    }, 2500);
    alert(currentLang === 'de'
      ? '✓ Alle Empfänger (BCC), Betreff und Musterschreiben in die Zwischenablage kopiert! Du kannst es jetzt direkt in dein Mailprogramm einfügen.'
      : '✓ Copied all BCC recipients, subject, and letter to clipboard!');
  });
}

async function dispatchBatchBrokerOptOutFromDossier() {
  if (!lastScanPayload || !lastScanPayload.email) {
    switchTab('unsubscribe');
    goToUnsubStep(1);
    alert(currentLang === 'de' ? 'Bitte gib deine E-Mail-Adresse im Unsubscribe Hub an.' : 'Please enter your email in the Unsubscribe Hub.');
    return;
  }
  await dispatchBatchBrokerOptOut();
}

async function markAllBrokersSent(showAlert = true) {
  try {
    if (!cachedMarketingBrokers) {
      const res = await fetch('/api/unsubscribe/brokers');
      const json = await res.json();
      if (json.success && (json.brokers || json.data)) {
        cachedMarketingBrokers = json.brokers || json.data;
      }
    }
    if (cachedMarketingBrokers) {
      cachedMarketingBrokers.forEach(b => {
        const key = b.privacy_email || b.name;
        removalStatusStore[key] = 'sent';
      });
      localStorage.setItem('selfscanner_unsub_statuses', JSON.stringify(removalStatusStore));
      fetchAndRenderMarketingBrokers();
      if (showAlert) {
        alert(currentLang === 'de' 
          ? '✓ Alle 7 Datenbroker wurden als "Anfrage gesendet" markiert!' 
          : '✓ All 7 data brokers marked as "Request Dispatched"!');
      }
    }
  } catch (err) {
    console.error('Failed to mark all brokers sent:', err);
  }
}

async function fetchAndRenderMarketingBrokers() {
  const container = document.getElementById('quickSelectBrokersGrid');
  if (!container) return;

  try {
    if (!cachedMarketingBrokers) {
      const res = await fetch('/api/unsubscribe/brokers');
      const json = await res.json();
      if (json.success && (json.brokers || json.data)) {
        cachedMarketingBrokers = json.brokers || json.data;
      }
    }

    if (!cachedMarketingBrokers || cachedMarketingBrokers.length === 0) return;

    container.innerHTML = cachedMarketingBrokers.map(b => {
      const desc = currentLang === 'de' ? b.desc_de : b.desc_en;
      const targetParam = b.privacy_email || b.name;
      const savedStatus = removalStatusStore[targetParam];
      let statusBadge = `<span class="text-[9px] text-slate-400 bg-slate-900 px-1 py-0.5 rounded">${b.category.split('&')[0]}</span>`;
      if (savedStatus === 'completed') {
        statusBadge = `<span class="text-[9px] text-emerald-400 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">${currentLang === 'de' ? '✓ Ausgetragen' : '✓ Erased'}</span>`;
      } else if (savedStatus === 'sent') {
        statusBadge = `<span class="text-[9px] text-amber-400 bg-amber-950 px-1.5 py-0.5 rounded border border-amber-800">${currentLang === 'de' ? '📨 Versendet' : '📨 Dispatched'}</span>`;
      }

      return `
        <div onclick="selectBrokerQuick('${b.name}', '${b.privacy_email || ''}', '${b.opt_out_url || ''}')" class="p-3 bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-indigo-600 rounded-xl cursor-pointer transition flex flex-col justify-between space-y-1.5 group shadow-sm">
          <div>
            <div class="flex items-center justify-between">
              <span class="font-bold text-white text-xs group-hover:text-indigo-300 transition">${b.name}</span>
              ${statusBadge}
            </div>
            <p class="text-[10px] text-slate-400 line-clamp-2 mt-0.5 leading-snug">${desc}</p>
          </div>
          <div class="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] text-indigo-400 font-semibold">
            <span>${currentLang === 'de' ? 'Auswählen' : 'Select'} ➔</span>
            <span class="text-slate-500 font-mono">${b.privacy_email || 'Web Opt-Out'}</span>
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    console.error('Failed to load marketing brokers:', err);
  }
}

// ==================== 7. SYSTEM VERSION & 1-CLICK UPDATE ====================
let currentVersionData = null;

async function initVersionTracker() {
  const revEl = document.getElementById('footerRevNumber');
  const badgeEl = document.getElementById('footerUpdateBadge');
  const dotEl = document.getElementById('updateDot');
  const textEl = document.getElementById('updateStatusText');

  try {
    const res = await fetch('/api/system/version');
    const json = await res.json();
    if (!json.success || !json.data) return;

    const data = json.data;
    currentVersionData = data;

    const localRev = data.local ? data.local.version_str : 'Rev. ?';
    if (revEl) revEl.textContent = localRev;

    const modalRev = document.getElementById('modalInstalledRev');
    if (modalRev) modalRev.textContent = localRev;

    if (badgeEl && textEl && dotEl) {
      if (data.update_available) {
        badgeEl.className = 'px-3 py-1 rounded-lg text-[11px] font-semibold border transition flex items-center space-x-1.5 cursor-pointer bg-amber-950/80 border-amber-600 text-amber-300 hover:bg-amber-900';
        dotEl.className = 'w-2 h-2 rounded-full bg-amber-400 animate-ping';
        textEl.textContent = currentLang === 'de' ? `⚠️ Update verfügbar! (${data.remote_commit || 'Neu'})` : `⚠️ Update available! (${data.remote_commit || 'New'})`;

        const modalStatus = document.getElementById('modalUpdateBadgeStatus');
        if (modalStatus) {
          modalStatus.className = 'px-2.5 py-1 rounded text-xs font-bold bg-amber-950 text-amber-300 border border-amber-700 animate-pulse';
          modalStatus.textContent = currentLang === 'de' ? `Update verfügbar (${data.remote_commit})` : `Update available (${data.remote_commit})`;
        }
      } else {
        badgeEl.className = 'px-3 py-1 rounded-lg text-[11px] font-semibold border transition flex items-center space-x-1.5 cursor-pointer bg-emerald-950/60 border-emerald-800 text-emerald-400 hover:bg-emerald-900/50';
        dotEl.className = 'w-2 h-2 rounded-full bg-emerald-400';
        textEl.textContent = currentLang === 'de' ? '✓ Auf neuestem Stand' : '✓ Up to date';

        const modalStatus = document.getElementById('modalUpdateBadgeStatus');
        if (modalStatus) {
          modalStatus.className = 'px-2.5 py-1 rounded text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
          modalStatus.textContent = currentLang === 'de' ? '✓ Auf neuestem Stand' : '✓ Up to date';
        }
      }
    }
  } catch (err) {
    console.warn('Version check failed:', err);
    if (textEl) textEl.textContent = currentLang === 'de' ? 'Offline' : 'Offline';
  }
}

function openUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (modal) modal.classList.remove('hidden');
}

function closeUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (modal) modal.classList.add('hidden');
}

function copyUpdateCommand(btn) {
  const cmd = "curl -sSL https://raw.githubusercontent.com/Schello805/Digital-Footprint-Scanner/main/update.sh | bash";
  navigator.clipboard.writeText(cmd).then(() => {
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ Kopiert!';
      setTimeout(() => btn.textContent = orig, 2000);
    }
  });
}

function copyInstallCommand(btn) {
  const cmd = "curl -sSL https://raw.githubusercontent.com/Schello805/Digital-Footprint-Scanner/main/install.sh | bash";
  navigator.clipboard.writeText(cmd).then(() => {
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ Kopiert!';
      setTimeout(() => btn.textContent = orig, 2000);
    }
  });
}

// ==================== 8. MULTI-USER AUTHENTICATION & PERSONAL SCANS ARCHIVE ====================
let currentUser = null;
let currentAuthMode = 'login'; // 'login' or 'register'
let currentGateAuthMode = 'register'; // Landing page default is registration

function setGateAuthMode(mode) {
  currentGateAuthMode = mode;
  const btnReg = document.getElementById('btnGateModeRegister');
  const btnLog = document.getElementById('btnGateModeLogin');
  const submitText = document.getElementById('gateSubmitText');
  const pwdHelp = document.getElementById('gatePwdHelpText');
  const errBanner = document.getElementById('gateAuthError');
  if (errBanner) errBanner.classList.add('hidden');

  if (mode === 'register') {
    if (btnReg) btnReg.className = 'py-2.5 rounded-lg bg-indigo-600 text-white transition cursor-pointer shadow';
    if (btnLog) btnLog.className = 'py-2.5 rounded-lg text-slate-400 hover:text-white transition cursor-pointer';
    if (submitText) submitText.textContent = currentLang === 'de' ? '🚀 Jetzt kostenlos registrieren & Scan starten' : '🚀 Create Free Account & Start Scan';
    if (pwdHelp) pwdHelp.textContent = currentLang === 'de' ? 'Mind. 8 Zeichen' : 'Min. 8 characters';
  } else {
    if (btnLog) btnLog.className = 'py-2.5 rounded-lg bg-indigo-600 text-white transition cursor-pointer shadow';
    if (btnReg) btnReg.className = 'py-2.5 rounded-lg text-slate-400 hover:text-white transition cursor-pointer';
    if (submitText) submitText.textContent = currentLang === 'de' ? '🔑 Anmelden & Scans öffnen' : '🔑 Sign In & Open Scans';
    if (pwdHelp) pwdHelp.textContent = '';
  }
}

function getAuthHeaders(extra = {}) {
  const headers = { ...extra };
  const token = localStorage.getItem('session_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function prefillScannerWithProfile(prefill) {
  if (!prefill) return;
  const fsFirstName = document.getElementById('fsFirstName');
  const fsLastName = document.getElementById('fsLastName');
  const fsName = document.getElementById('fsName');
  const fsUsername = document.getElementById('fsUsername');
  const fsEmail = document.getElementById('fsEmail');
  const fsDomain = document.getElementById('fsDomain');
  const fsCity = document.getElementById('fsCity');
  const fsEmployer = document.getElementById('fsEmployer');

  let filledCount = 0;

  let pFirst = prefill.first_name || '';
  let pLast = prefill.last_name || '';
  if (!pFirst && !pLast && prefill.name) {
    const parts = prefill.name.trim().split(/\s+/);
    pFirst = parts[0] || '';
    pLast = parts.slice(1).join(' ') || '';
  }

  if (fsFirstName && !fsFirstName.value.trim() && pFirst) {
    fsFirstName.value = pFirst;
    filledCount++;
  }
  if (fsLastName && !fsLastName.value.trim() && pLast) {
    fsLastName.value = pLast;
    filledCount++;
  }
  if (fsName) {
    const combined = [fsFirstName ? fsFirstName.value : '', fsLastName ? fsLastName.value : ''].filter(Boolean).join(' ');
    fsName.value = combined || prefill.name || '';
  }

  if (fsUsername && !fsUsername.value.trim() && prefill.username) {
    fsUsername.value = prefill.username;
    filledCount++;
  }
  if (fsEmail && !fsEmail.value.trim() && prefill.email) {
    fsEmail.value = prefill.email;
    filledCount++;
  }
  if (fsDomain && !fsDomain.value.trim() && prefill.domain) {
    fsDomain.value = prefill.domain;
    filledCount++;
  }
  if (fsCity && !fsCity.value.trim() && prefill.city) {
    fsCity.value = prefill.city;
    filledCount++;
  }
  if (fsEmployer && !fsEmployer.value.trim() && prefill.employer) {
    fsEmployer.value = prefill.employer;
    filledCount++;
  }

  const banner = document.getElementById('prefillProfileBanner');
  const textEl = document.getElementById('prefillProfileText');
  if (banner && filledCount > 0) {
    banner.classList.remove('hidden');
    if (textEl) {
      const displayName = prefill.name || [pFirst, pLast].filter(Boolean).join(' ') || prefill.username || prefill.email;
      textEl.textContent = currentLang === 'de'
        ? `Angemeldet als ${displayName}: Name, E-Mail & Domain wurden automatisch für den 1-Klick-Scan vorausgefüllt.`
        : `Signed in as ${displayName}: Name, email & domain pre-filled automatically for 1-click scan.`;
    }
  }
}

function clearFullScanForm() {
  ['fsFirstName', 'fsLastName', 'fsName', 'fsUsername', 'fsEmail', 'fsPassword', 'fsDomain', 'fsPhone', 'fsCity', 'fsEmployer', 'fsKeywords'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const banner = document.getElementById('prefillProfileBanner');
  if (banner) banner.classList.add('hidden');
}

async function handleGateAuthSubmit(e) {
  e.preventDefault();
  const emailInput = document.getElementById('gateAuthEmail');
  const pwdInput = document.getElementById('gateAuthPassword');
  const errBanner = document.getElementById('gateAuthError');
  const spinner = document.getElementById('gateSpinner');
  const submitBtn = document.getElementById('btnGateAuthSubmit');

  const email = emailInput ? emailInput.value.trim() : '';
  const password = pwdInput ? pwdInput.value : '';

  if (!email || !password) return;

  if (errBanner) errBanner.classList.add('hidden');
  if (spinner) spinner.classList.remove('hidden');
  if (submitBtn) submitBtn.disabled = true;

  const endpoint = currentGateAuthMode === 'register' ? '/api/auth/register' : '/api/auth/login';

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const json = await res.json();

    if (json.success) {
      if (json.token) {
        localStorage.setItem('session_token', json.token);
      }
      if (pwdInput) pwdInput.value = '';
      await checkAuthStatus();
    } else {
      if (errBanner) {
        errBanner.textContent = json.error || (currentLang === 'de' ? 'Fehler bei der Authentifizierung' : 'Authentication failed');
        errBanner.classList.remove('hidden');
      }
    }
  } catch (err) {
    if (errBanner) {
      errBanner.textContent = currentLang === 'de' ? 'Verbindungsfehler zum Server' : 'Connection error to server';
      errBanner.classList.remove('hidden');
    }
  } finally {
    if (spinner) spinner.classList.add('hidden');
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function checkAuthStatus() {
  try {
    // Check if token was provided in URL callback (e.g. from OAuth redirect)
    const urlParams = new URLSearchParams(window.location.search);
    const queryAuthToken = urlParams.get('auth_token');
    if (queryAuthToken) {
      localStorage.setItem('session_token', queryAuthToken);
      urlParams.delete('auth_token');
      urlParams.delete('login_success');
      const cleanSearch = urlParams.toString() ? '?' + urlParams.toString() : '';
      const cleanUrl = window.location.pathname + cleanSearch + window.location.hash;
      window.history.replaceState({}, document.title, cleanUrl);
    }

    const res = await fetch('/api/auth/me', {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const json = await res.json();
    const loginBtn = document.getElementById('btnHeaderLogin');
    const userDropdown = document.getElementById('headerUserDropdown');
    const emailText = document.getElementById('headerUserEmailText');
    const avatarImg = document.getElementById('headerUserAvatar');
    const gateContainer = document.getElementById('authGateContainer');
    const navContainer = document.getElementById('appNavContainer');
    const mainContainer = document.getElementById('appMainContainer');

    if (json.success && json.authenticated && json.user) {
      currentUser = json.user;
      if (gateContainer) gateContainer.classList.add('hidden');
      if (navContainer) navContainer.classList.remove('hidden');
      if (mainContainer) mainContainer.classList.remove('hidden');

      if (loginBtn) loginBtn.classList.add('hidden');
      if (userDropdown) userDropdown.classList.remove('hidden');
      if (emailText) emailText.textContent = currentUser.email;

      if (avatarImg) {
        if (currentUser.avatar_url) {
          avatarImg.src = currentUser.avatar_url;
          avatarImg.classList.remove('hidden');
        } else {
          avatarImg.classList.add('hidden');
        }
      }

      // Automatically prefill scanner form from profile
      if (currentUser.prefill) {
        prefillScannerWithProfile(currentUser.prefill);
      }

      closeAuthModal();
      await refreshUserScans();
    } else {
      currentUser = null;
      if (gateContainer) gateContainer.classList.remove('hidden');
      if (navContainer) navContainer.classList.add('hidden');
      if (mainContainer) mainContainer.classList.add('hidden');

      if (loginBtn) loginBtn.classList.remove('hidden');
      if (userDropdown) userDropdown.classList.add('hidden');
      if (avatarImg) avatarImg.classList.add('hidden');

      closeAuthModal();
    }
  } catch (err) {
    console.warn('Auth status check failed:', err);
  }
}

function handleHeaderLoginClick() {
  const gateContainer = document.getElementById('authGateContainer');
  // If gate screen is visible, seamlessly activate login tab without popup
  if (gateContainer && !gateContainer.classList.contains('hidden')) {
    setGateAuthMode('login');
    const emailInput = document.getElementById('gateEmail');
    if (emailInput) {
      emailInput.focus();
      emailInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return;
  }
  openAuthModal();
}

function openAuthModal() {
  const gateContainer = document.getElementById('authGateContainer');
  // Prevent duplicate floating modal over the landing gate
  if (gateContainer && !gateContainer.classList.contains('hidden')) {
    setGateAuthMode('login');
    const emailInput = document.getElementById('gateEmail');
    if (emailInput) {
      emailInput.focus();
      emailInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return;
  }
  const modal = document.getElementById('authModal');
  if (modal) {
    modal.classList.remove('hidden');
    const errBanner = document.getElementById('authErrorBanner');
    if (errBanner) errBanner.classList.add('hidden');
  }
}

function closeAuthModal() {
  const modal = document.getElementById('authModal');
  if (modal) modal.classList.add('hidden');
}

function switchAuthMode(mode) {
  currentAuthMode = mode;
  const tabLogin = document.getElementById('tabAuthLogin');
  const tabReg = document.getElementById('tabAuthRegister');
  const submitText = document.getElementById('authSubmitText');
  const privacyNote = document.getElementById('authPrivacyNote');
  const errBanner = document.getElementById('authErrorBanner');
  if (errBanner) errBanner.classList.add('hidden');

  if (mode === 'register') {
    tabLogin.className = 'flex-1 py-1.5 font-medium rounded-lg transition text-slate-400 hover:text-white';
    tabReg.className = 'flex-1 py-1.5 font-bold rounded-lg transition text-white bg-indigo-600 shadow';
    if (submitText) submitText.textContent = currentLang === 'de' ? 'Kostenlos registrieren' : 'Create Free Account';
    if (privacyNote) privacyNote.classList.remove('hidden');
  } else {
    tabReg.className = 'flex-1 py-1.5 font-medium rounded-lg transition text-slate-400 hover:text-white';
    tabLogin.className = 'flex-1 py-1.5 font-bold rounded-lg transition text-white bg-indigo-600 shadow';
    if (submitText) submitText.textContent = currentLang === 'de' ? 'Anmelden' : 'Sign In';
    if (privacyNote) privacyNote.classList.add('hidden');
  }
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const emailInput = document.getElementById('authEmail');
  const pwdInput = document.getElementById('authPassword');
  const errBanner = document.getElementById('authErrorBanner');
  const spinner = document.getElementById('authSpinner');
  const submitBtn = document.getElementById('authSubmitBtn');

  const email = emailInput.value.trim();
  const password = pwdInput.value;

  if (!email || !password) return;

  if (errBanner) errBanner.classList.add('hidden');
  if (spinner) spinner.classList.remove('hidden');
  if (submitBtn) submitBtn.disabled = true;

  const endpoint = currentAuthMode === 'register' ? '/api/auth/register' : '/api/auth/login';

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const json = await res.json();

    if (json.success) {
      if (json.token) {
        localStorage.setItem('session_token', json.token);
      }
      closeAuthModal();
      pwdInput.value = '';
      await checkAuthStatus();
    } else {
      if (errBanner) {
        errBanner.textContent = json.error || (currentLang === 'de' ? 'Fehler bei der Authentifizierung' : 'Authentication failed');
        errBanner.classList.remove('hidden');
      }
    }
  } catch (err) {
    if (errBanner) {
      errBanner.textContent = currentLang === 'de' ? 'Verbindungsfehler zum Server' : 'Connection error to server';
      errBanner.classList.remove('hidden');
    }
  } finally {
    if (spinner) spinner.classList.add('hidden');
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function performLogout() {
  try {
    await fetch('/api/auth/logout', { 
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include'
    });
  } catch (e) {
    // quiet
  }
  localStorage.removeItem('session_token');
  currentUser = null;
  await checkAuthStatus();
}

function openUserScansModal() {
  const modal = document.getElementById('userScansModal');
  if (modal) {
    modal.classList.remove('hidden');
    refreshUserScans();
  }
}

function closeUserScansModal() {
  const modal = document.getElementById('userScansModal');
  if (modal) modal.classList.add('hidden');
}

async function refreshUserScans() {
  const container = document.getElementById('userScansListContainer');
  const tabContainer = document.getElementById('userScansTabListContainer');
  if (!container && !tabContainer) return;

  if (container) container.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">Lade gespeicherte Scans...</div>`;
  if (tabContainer) tabContainer.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">Lade gespeicherte Scans...</div>`;

  try {
    const res = await fetch('/api/user/scans', {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const json = await res.json();

    const scans = (json.success && json.scans) ? json.scans : [];
    const count = scans.length;

    const badgeHeader = document.getElementById('headerUserScansBadge');
    const badgeNav = document.getElementById('tabNavScansBadge');
    const badgeCount = document.getElementById('tabScansCountBadge');

    if (badgeHeader) badgeHeader.textContent = count;
    if (badgeNav) badgeNav.textContent = count;
    if (badgeCount) badgeCount.textContent = `${count} ${currentLang === 'de' ? 'archiviert' : 'archived'}`;

    if (count === 0) {
      const emptyHtml = `
        <div class="p-10 text-center bg-slate-950 border border-slate-800 rounded-2xl space-y-3">
          <span class="text-4xl block">📂</span>
          <div class="font-bold text-white text-base">${currentLang === 'de' ? 'Noch keine Scans gespeichert' : 'No saved scans yet'}</div>
          <p class="text-slate-400 text-xs max-w-md mx-auto">${currentLang === 'de' ? 'Führe deinen ersten Vollscan durch – deine Berichte und Dossiers werden hier automatisch für dich archiviert.' : 'Execute your first full scan – your intelligence reports will be archived here automatically.'}</p>
          <div class="pt-3">
            <button onclick="closeUserScansModal(); switchTab('fullscan');" class="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition shadow cursor-pointer">
              ${currentLang === 'de' ? '🚀 Zum Vollscan Cockpit' : '🚀 To Full Scan Cockpit'}
            </button>
          </div>
        </div>
      `;
      if (container) container.innerHTML = emptyHtml;
      if (tabContainer) tabContainer.innerHTML = emptyHtml;
      return;
    }

    const itemsHtml = scans.map(s => {
      const targetLabel = s.target_name || (s.target_handle ? `@${s.target_handle}` : (s.target_email || 'Unbekanntes Ziel'));
      const handleSub = s.target_handle ? `@${s.target_handle}` : (s.target_email || '-');
      const dateStr = s.created_at ? s.created_at.replace('T', ' ').slice(0, 16) : '-';
      
      let badgeColor = 'emerald';
      if (s.exposure_score >= 70) badgeColor = 'rose';
      else if (s.exposure_score >= 35) badgeColor = 'amber';

      return `
        <div class="p-4 bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm transition">
          <div class="space-y-1">
            <div class="flex items-center space-x-2">
              <span class="font-bold text-white text-sm">${targetLabel}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${badgeColor}-950 text-${badgeColor}-400 border border-${badgeColor}-800 font-mono">
                ${s.exposure_score}% ${s.exposure_level}
              </span>
            </div>
            <div class="text-[11px] text-slate-400 font-mono flex items-center space-x-3">
              <span>Handle: ${handleSub}</span>
              <span>•</span>
              <span class="text-indigo-400 font-semibold">${s.profiles_found} Profile (${s.high_confidence_matches} verifiziert)</span>
              <span>•</span>
              <span>📅 ${dateStr}</span>
            </div>
          </div>
          <div class="flex items-center space-x-2 self-end sm:self-center">
            <button onclick="loadSavedScan(${s.id})" class="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition flex items-center space-x-1 cursor-pointer">
              <span>📂 Dossier öffnen</span>
            </button>
            <button onclick="deleteSavedScan(${s.id})" title="Löschen" class="p-1.5 rounded-lg border border-slate-800 hover:border-rose-800 hover:bg-rose-950/50 text-slate-400 hover:text-rose-400 transition cursor-pointer">
              🗑️
            </button>
          </div>
        </div>
      `;
    }).join('');

    if (container) container.innerHTML = itemsHtml;
    if (tabContainer) tabContainer.innerHTML = itemsHtml;

  } catch (err) {
    const errHtml = `<div class="p-6 text-center text-rose-400 text-xs">Fehler beim Laden der Scans: ${err.message}</div>`;
    if (container) container.innerHTML = errHtml;
    if (tabContainer) tabContainer.innerHTML = errHtml;
  }
}

async function loadSavedScan(scanId) {
  try {
    const res = await fetch(`/api/user/scans/${scanId}`, {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const json = await res.json();
    if (!json.success || !json.scan) {
      alert(currentLang === 'de' ? 'Scan konnte nicht geladen werden.' : 'Could not load scan.');
      return;
    }

    closeUserScansModal();
    switchTab('fullscan');

    const results = json.scan.results;
    const payload = json.scan.payload;

    renderFullReport(results, payload);

    const savedNotice = document.getElementById('scanSavedNotification');
    if (savedNotice) savedNotice.classList.remove('hidden');

    // Smooth scroll to the report
    setTimeout(() => {
      const dossier = document.getElementById('fullReportContainer');
      if (dossier) {
        dossier.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 200);

  } catch (err) {
    alert('Fehler beim Öffnen des Scans: ' + err.message);
  }
}

async function deleteSavedScan(scanId) {
  const confirmMsg = currentLang === 'de' 
    ? 'Möchtest du diesen gespeicherten Scan wirklich aus deinem Archiv löschen?' 
    : 'Are you sure you want to delete this scan from your archive?';
  
  if (!confirm(confirmMsg)) return;

  try {
    const res = await fetch(`/api/user/scans/${scanId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const json = await res.json();
    if (json.success) {
      await refreshUserScans();
    }
  } catch (err) {
    alert('Löschfehler: ' + err.message);
  }
}

// ==================== THEME MANAGEMENT ====================
let currentTheme = localStorage.getItem('selfscanner_theme') || 'dark';

function initTheme() {
  applyTheme(currentTheme);
}

function toggleTheme() {
  currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('selfscanner_theme', currentTheme);
  applyTheme(currentTheme);
}

function applyTheme(theme) {
  const root = document.documentElement;
  const icon = document.getElementById('themeIcon');
  const text = document.getElementById('themeText');
  if (theme === 'light') {
    root.classList.add('theme-light');
    root.classList.remove('dark');
    if (icon) icon.textContent = '🌙';
    if (text) text.textContent = currentLang === 'de' ? 'Dunkel' : 'Dark';
  } else {
    root.classList.remove('theme-light');
    root.classList.add('dark');
    if (icon) icon.textContent = '☀️';
    if (text) text.textContent = currentLang === 'de' ? 'Hell' : 'Light';
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  setLanguage(currentLang);
  updateGdprLetter();
  updateDisclaimerContent();
  fetchAndRenderMarketingBrokers();
  initVersionTracker();
  checkAuthStatus();
});
