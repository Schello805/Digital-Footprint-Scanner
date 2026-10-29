# 🔍 Selfscanner – Digital Footprint & OSINT Privacy Auditor

**Selfscanner** ist ein modulares Open-Source-Intelligence-Tool (OSINT) zur automatisierten Überprüfung, Korrelation und Absicherung des eigenen digitalen Fußabdrucks im Internet.

> **Das Problem:** Ein Name alleine (wie *Michael Schmidt* oder *Max Müller*) liefert im Internet Hunderte von Namensvettern und False Positives.  
> **Die Lösung:** Selfscanner korreliert Name, Wohnort, Arbeitgeber, Aliase, Telefon und E-Mail zu einem ganzheitlichen Personenprofil und filtert fremde Namensvetter über intelligente Bio- und Inhaltsanalysen heraus.

---

## 🚀 Kernfunktionen & Module

### 1. 🎯 Identitäts- & Footprint-Audit (Multi-Target Correlation)
- **Ganzheitliche Angriffsflächen-Berechnung:** Berechnet den **Digital Exposure Index (0–100)** basierend auf Kombinationen aus Name + Wohnort + Arbeitgeber + Telefon.
- **Bedrohungsvektoren-Analyse:** Erkennt Risiken für Spear Phishing, Doxing, Meldeadress-Rückschlüsse und SIM-Swapping.
- **DSGVO Art. 17 Generator:** Erzeugt mit einem Klick rechtssichere Musterschreiben auf Löschung („Recht auf Vergessenwerden“) sowie Direktlinks zum Google-Entfernungsantrag.

### 2. 👤 Smarter Username-Scanner mit Bio-Matching
- **Anti-False-Positive Filter:** Durchsucht über 40 Plattformen parallel (GitHub, Reddit, Twitter, Medium, Steam, Dev.to etc.) und extrahiert den Bio-Text der Seite.
- **Kontext-Scoring:** Prüft, ob im Profil dein echter Name, dein Wohnort oder deine Interessen auftauchen:
  - 🟢 **Hohe Wahrscheinlichkeit (z. B. 95% Match):** Dein Name & Wohnort wurden im Profil gefunden.
  - 🟡 **Möglicher Treffer:** Einzelne Keywords stimmen überein.
  - ⚪ **Namensvetter:** Keine Kontextübereinstimmung.
- **Filter-Funktion:** Ermöglicht das sofortige Ausblenden unzutreffender Namensvetter.

### 3. 📬 E-Mail-Permutator & Breach-Check
- Generiert realistische Firmen- und Privat-E-Mail-Permutationen (`vorname.nachname@...`, `v.nachname@...`, `vorname@...`).
- 1-Klick-Übergabe an den **HaveIBeenPwned k-Anonymity Scanner** zum Aufdecken vergessener Accounts in Datenpannen.

### 4. 📞 Rufnummern-Reconnaissance
- Erkennt Vorwahlen, Ortsnetze (z. B. *089 München*, *030 Berlin*) und Mobilfunkanbieter (*Telekom, Vodafone, O2, 1&1*).
- Generiert zielgerichtete Abfragen für Spam-Verzeichnisse (*Tellows*), Telefonbücher (*Das Örtliche*) und ungeschützte Webseiten.

### 5. 📸 EXIF- & Metadaten-Inspektor (GPS-Tracker & Privacy Sanitizer)
- Liest versteckte Kameradaten, Objektiv und Zeitstempel aus Fotos aus.
- **GPS-Mapping:** Konvertiert geographische GPS-Koordinaten und zeigt den Aufnahmeort auf einer **OpenStreetMap-Karte** an.
- **1-Klick-Bereiniger:** Entfernt sämtliche Metadaten restlos für sicheres Teilen.

### 6. 🌐 Domain- & E-Mail-Sicherheits-Audit
- Prüft **SPF** und **DMARC** auf Mail-Spoofing-Schwachstellen (Schutz vor Phishing im eigenen Namen).
- Identifiziert DNS- und Mail-Provider (*Cloudflare, Google Workspace, Microsoft 365, ProtonMail*).

### 7. 🔎 Google Dorking Generator
- Erstellt strukturierte Präzisionsabfragen für Handelsregister (*North Data*, *Unternehmensregister*), offene PDF-Dokumente und Paste-Dumps (*Pastebin*).

---

## 🛠️ Schnellstart

```bash
cd /Users/michael/Programmerierung/Selfscanner
./venv/bin/python run.py
```

Öffne im Browser: **[http://localhost:8000](http://localhost:8000)**

---

## 🔐 Datenschutz
Alle Analysen (EXIF, DNS, k-Anonymity) laufen lokal oder über mathematische Hashes. Es werden keine Daten auf externen Servern gespeichert.
