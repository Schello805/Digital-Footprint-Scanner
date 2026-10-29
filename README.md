<p align="center">
  <img src="app/static/img/logo.png" width="180" alt="Digital Footprint Scanner Logo" style="border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.3);" />
</p>

# 🔍 Digital Footprint Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v3-38B2AC.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OSINT Privacy](https://img.shields.io/badge/Privacy-by--Design-green.svg)]()

> **An ethical, automated Digital Footprint & OSINT Privacy Suite** designed to audit, correlate, and remediate personal exposures across the public internet.

---

## 🌟 Key Highlights

### 🚀 1-Click Automated Full Scan (All-in-One Cockpit)
- No need to click through multiple tabs.
- Enter your identifiers once (**Full Name, Handle/Username, Email, Phone, Location, Employer, Domain, or Password**) and trigger an **orchestrated concurrent audit in ~2 seconds**.

### 📄 DIN A4 Confidential Dossier / Printable Fact Sheet
- Formatted as an executive **OSINT Intelligence Dossier**:
  - File Reference Number, Timestamp, Silhouette, and Official Risk Stamp.
  - Profile attribute sheet, breach status, and verified platforms table.
  - Forensic threat vector analysis and direct data broker removal links.
- **Optimized for DIN A4 Print & PDF Export** (`@media print` clean contrast layout).

### 👤 Handle Recon with Smart Bio-Matching (Anti-False-Positive)
- Inspired by tools like *Sherlock* and *FootprintIQ's LENSiQ™* engine.
- Queries **40+ platforms** (GitHub, Reddit, Twitter/X, Medium, Steam, Dev.to, Pinterest, etc.).
- **Content & Bio Scraping:** Inspects page title and meta description to match your real name or location.
- **Confidence Scoring:** Categorizes findings into 🟢 **High Match (e.g. 95%)**, 🟡 **Likely**, or ⚪ **Coincidental Name** (filters out same-name strangers).

### 🛡️ Zero-Knowledge Password & Free Breach Engine
- **k-Anonymity SHA-1 Model:** Your password **never** leaves your local machine. Only the first 5 characters of the hash are checked against over **800 million known leaked passwords**.
- **Automatic Free Breach Intelligence:** Integrates the **XposedOrNot OSINT API** for instant, free breach lookups without mandatory paid keys, while fully supporting official **HaveIBeenPwned v3 API keys** if provided.

### 📬 Public Mailing List Recon (GNU Mailman & MARC)
- Queries **MARC.info** (Mailing List ARChives with over 1,500 public lists) live to uncover archived emails.
- Generates precision dorks for **GNU Mailman / Pipermail directories** (`inurl:pipermail`), *The Mail Archive*, *Google Groups*, and developer lists (Debian, Ubuntu, Apache).

### 🌐 Domain & Email Spoofing Audit (SPF / DMARC)
- Audits SPF records (`-all` vs `~all` vs permissive) and DMARC policies (`p=reject`, `p=quarantine`, `p=none`) to check whether attackers can impersonate you or send phishing emails in your name.
- Identifies infrastructure providers (Cloudflare, Google Workspace, Microsoft 365, ProtonMail).

### 📸 EXIF & Geolocation Metadata Inspector
- Inspects hidden camera metadata, lens, software, and creation timestamps in photos.
- **GPS Mapping:** Converts EXIF GPS rational coordinates into decimal latitude/longitude and visualizes the capture location on an interactive **OpenStreetMap (Leaflet.js)** map.
- **1-Click Privacy Sanitizer:** Strips all metadata completely and exports a sanitized image for safe sharing.

### 🛡️ Remediation Plan & Data Broker Opt-Out (FootprintIQ Inspired)
- Moves from diagnosis to solution:
  - **Direct Deactivation Links:** 1-click links to the exact account deletion pages of found platforms (GitHub, Reddit, Twitter, Medium, Steam, etc.).
  - **Data Broker Opt-Out:** Direct removal guides for people-search directories (*Yasni, Das Telefonbuch, 11880, Radaris*).
  - **Art. 17 GDPR Erasure Request:** Ready-to-send legal notice exercising the *Right to be Forgotten* plus links to official search removal request tools.

### 📬 Incogni-Style Mailing List & Marketing Opt-Out Hub
- **⚡ 1-Click Multi-Broker Batch Opt-Out:** Send a confidential multi-recipient (BCC) statutory objection and erasure request (Art. 21(2) & Art. 17 GDPR) to all 7 major data brokers and address aggregators simultaneously (*Schober, microm, Acxiom, LiveRamp, Criteo, Experian, Yasni*).
- **1-Click RFC 2369 & Mailman Daemon Command:** Automatically generates `mailto:<list>-request@<domain>?subject=unsubscribe` links for instant de-registration from standard mailing lists without manual review.
- **GDPR Art. 21 Direct Marketing Objection:** Generates legally binding opt-out and erasure notices (Art. 21(2) & Art. 17 GDPR) with 1-click `mailto:` dispatch from your local email client.
- **Top Marketing Broker Directory & Status Tracker:** Curated opt-out directory for major DACH and global marketing data brokers with direct opt-out portals, privacy contact emails, and local removal status logging.

### 🌐 Bilingual Interface (English & German)
- **English is default**, with a 1-click language switcher (`[ EN | DE ]`) in the navigation bar.

---

## 🛠️ Quickstart

### Prerequisites
- Python 3.10 or newer

### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/Schello805/Digital-Footprint-Scanner.git
cd Digital-Footprint-Scanner
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python3 run.py
```

Open your browser at: **[http://localhost:8000](http://localhost:8000)**

---

## 📁 Repository Structure

```
Digital-Footprint-Scanner/
├── app/
│   ├── config.py                 # Application settings & optional API keys
│   ├── main.py                   # FastAPI application, routing & API endpoints
│   ├── modules/
│   │   ├── full_scanner.py       # Orchestrated 1-Click full audit pipeline
│   │   ├── username_checker.py   # Sherlock-style handle scanner with bio-matcher
│   │   ├── breach_checker.py     # k-Anonymity password check & free breach intelligence
│   │   ├── mailing_list_checker.py # MARC.info & GNU Mailman archive checker
│   │   ├── domain_recon.py       # DNS resolver & SPF/DMARC mail security audit
│   │   ├── phone_recon.py        # Carrier, area code & reputation lookup
│   │   ├── exif_inspector.py     # Image metadata, GPS mapping & EXIF scrubber
│   │   ├── cleanup_guide.py      # Direct account deletion & data broker opt-out guides
│   │   ├── identity_auditor.py   # Multi-attribute threat vector analysis & GDPR generator
│   │   ├── email_permutator.py   # Probable corporate & personal email generator
│   │   └── dork_builder.py       # Precision Google dorking query builder
│   ├── static/
│   │   ├── css/
│   │   │   ├── tailwind.min.css  # Standalone local Tailwind CSS bundle
│   │   │   ├── custom.css        # Cyber theme & DIN A4 printable dossier styling
│   │   │   └── leaflet.css       # Local Leaflet map styles
│   │   └── js/
│   │       ├── app.js            # Reactive UI, i18n engine (EN/DE) & SSE client
│   │       └── leaflet.js        # Local Leaflet map library
│   └── templates/
│       └── index.html            # Main web cockpit & DIN A4 dossier template
├── tests/
│   ├── test_core.py              # Unit & integration test suite
│   └── test_server.py            # Static asset delivery verification
├── requirements.txt              # Production dependencies
├── run.py                        # Entrypoint script (Uvicorn server)
└── README.md                     # Documentation (English)
```

---

## 🔐 Privacy & Ethical Boundaries
Digital Footprint Scanner operates strictly on the principle of **Ethical OSINT**:
- All analyses query publicly accessible metadata and open records.
- No logins are bypassed, no credentials are stolen, and no private data is collected or transmitted to third parties.
- All password checks utilize mathematically proven **k-Anonymity** where plaintext passwords are never transmitted.

---

## ⚖️ Legal Disclaimer & Terms of Use

### 1. Intended Purpose & Authorization
**Digital Footprint Scanner** is developed strictly for **defensive self-auditing** (exercising the fundamental right of access pursuant to **Art. 15 GDPR** / international privacy regulations) and authorized security awareness audits.
- Conducting OSINT reconnaissance or building intelligence dossiers on unconsenting third parties without explicit authorization is strictly prohibited and may violate applicable privacy laws (e.g. Art. 6 GDPR, German Criminal Code § 126a - *Doxing / Endangering Dissemination of Personal Data*).
- Users are solely responsible for ensuring that their use conforms to all local, national, and international laws.

### 2. Limitation of Liability
This project is open-source software distributed under the MIT License on an "as is" and "as available" basis. Under no circumstances shall the author(s), developers, or contributors be liable for any direct, indirect, incidental, or consequential damages resulting from the misuse or unauthorized operation of this tool.

### 3. No Legal Advice
The provided **Article 17 GDPR erasure request templates** and data remediation resources are automated drafts provided for educational and convenience purposes. They do not constitute certified legal advice. Consult a licensed legal professional or data protection authority for binding counsel.

### 4. Zero Data Collection
This application operates **100% locally**. No scanned targets, personal identifiers, network payloads, or user credentials are ever stored in a central database or transmitted to any external telemetry server.
