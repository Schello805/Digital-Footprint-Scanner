from typing import Dict, Any, List

PLATFORM_CLEANUP_DIRECTORIES: Dict[str, Dict[str, str]] = {
    "GitHub": {
        "delete_url": "https://github.com/settings/admin",
        "instructions": "Navigate to the bottom 'Danger Zone' and click 'Delete your account'.",
        "instructions_de": "Navigiere ganz nach unten zu 'Danger Zone' und klicke auf 'Delete your account'."
    },
    "Reddit": {
        "delete_url": "https://www.reddit.com/settings/account",
        "instructions": "Scroll to the bottom and click 'Delete account'.",
        "instructions_de": "Ganz nach unten scrollen und auf 'Account löschen' (Delete account) klicken."
    },
    "Twitter / X": {
        "delete_url": "https://x.com/settings/deactivate",
        "instructions": "Select 'Your account' -> 'Deactivate your account'. Permanently deleted after 30 days.",
        "instructions_de": "Wähle 'Dein Account' -> 'Meinen Account deaktivieren'. Nach 30 Tagen wird das Konto dauerhaft gelöscht."
    },
    "Medium": {
        "delete_url": "https://medium.com/me/settings/security",
        "instructions": "Under 'Security', scroll down to 'Delete account'.",
        "instructions_de": "Unter 'Security' ganz nach unten scrollen zu 'Delete account'."
    },
    "Pinterest": {
        "delete_url": "https://www.pinterest.com/settings/account-settings/",
        "instructions": "At the bottom of Account management, click 'Delete account'.",
        "instructions_de": "Klicke ganz unten unter 'Kontoverwaltung' auf 'Konto löschen'."
    },
    "Steam": {
        "delete_url": "https://help.steampowered.com/en/wizard/HelpDeleteAccount",
        "instructions": "Follow the official Steam support account deletion wizard.",
        "instructions_de": "Support-Assistenten zur dauerhaften Kontolöschung durchlaufen."
    },
    "Spotify": {
        "delete_url": "https://support.spotify.com/en/article/close-account/",
        "instructions": "Follow the official account closure instructions.",
        "instructions_de": "Folge dem offiziellen Kündigungs- und Kontoschließungsassistenten."
    },
    "Dev.to": {
        "delete_url": "https://dev.to/settings/misc",
        "instructions": "Under 'Danger Zone' at the bottom, click 'Delete Account'.",
        "instructions_de": "Ganz unten unter 'Danger Zone' auf 'Delete Account' klicken."
    },
    "GitLab": {
        "delete_url": "https://gitlab.com/-/profile/account",
        "instructions": "Under 'Delete account', click the confirmation button.",
        "instructions_de": "Unter 'Delete account' auf den roten Bestätigungs-Button klicken."
    },
    "Gravatar": {
        "delete_url": "https://en.gravatar.com/profiles/edit/#account-deactivation",
        "instructions": "Remove profile avatar and select account deactivation.",
        "instructions_de": "Profil-Avatar entfernen und Deaktivierung auswählen."
    },
    "Linktree": {
        "delete_url": "https://linktr.ee/admin/my-account",
        "instructions": "Click 'Delete account' at the bottom of the page.",
        "instructions_de": "Unten auf 'Delete account' klicken."
    },
    "About.me": {
        "delete_url": "https://about.me/settings/account",
        "instructions": "Under Account Settings, choose 'Delete your account'.",
        "instructions_de": "Unter Account Settings ganz unten 'Delete your account' wählen."
    },
    "BuyMeACoffee": {
        "delete_url": "https://www.buymeacoffee.com/settings",
        "instructions": "Under Account Settings, choose 'Delete account'.",
        "instructions_de": "In den Account Settings ganz unten 'Delete account' wählen."
    },
    "Patreon": {
        "delete_url": "https://www.patreon.com/settings/account",
        "instructions": "Under Account Settings, select 'Delete account'.",
        "instructions_de": "Unter Kontoeinstellungen ganz unten 'Konto löschen' wählen."
    },
    "Tumblr": {
        "delete_url": "https://www.tumblr.com/settings/account",
        "instructions": "Click 'Delete account' at the bottom of the settings.",
        "instructions_de": "Ganz unten auf 'Account löschen' klicken."
    },
    "Vimeo": {
        "delete_url": "https://vimeo.com/settings/account",
        "instructions": "Under 'Account', choose 'Delete account'.",
        "instructions_de": "Unter 'Account' ganz unten 'Delete account' wählen."
    },
    "SoundCloud": {
        "delete_url": "https://soundcloud.com/settings",
        "instructions": "Click 'Delete account' at the end of the settings page.",
        "instructions_de": "Am Seitenende auf 'Delete account' klicken."
    }
}

DATA_BROKERS: List[Dict[str, str]] = [
    {
        "name": "Das Örtliche & Das Telefonbuch (DTM Portal)",
        "search_url_template": "https://www.dasoertliche.de/?kw={}",
        "opt_out_url": "https://www.dtme.de/ihr-eintrag/ihr-privater-eintrag/",
        "desc": "Official German directory for phone numbers, mobile and residential addresses.",
        "desc_de": "Offizielle deutsche Telefon- und Teilnehmerverzeichnisse (Festnetz, Mobilfunk, Anschrift).",
        "action": "Submit official deletion form via Deutsche Tele Medien portal.",
        "action_de": "Kostenloses Online-Austragungsformular der Deutschen Tele Medien (DTM) zur Sperrung einreichen."
    },
    {
        "name": "11880.com (DACH Directory Services)",
        "search_url_template": "https://www.11880.com/suche/{}",
        "opt_out_url": "https://unternehmen.11880.com/kontakt",
        "desc": "Public directory with personal and company addresses.",
        "desc_de": "Öffentliches Teilnehmer- und Branchenverzeichnis mit Kontaktdaten.",
        "action": "Submit entry deletion notice via official customer contact form.",
        "action_de": "Löschungsantrag für Verzeichniseintrag über das 11880-Kontaktformular einreichen."
    }
]

def get_remediation_guide(found_platforms: List[Dict[str, Any]], name: str = "", email: str = "") -> Dict[str, Any]:
    """
    Produces actionable account deletion steps and direct opt-out links for data brokers.
    """
    account_guides = []
    for p in found_platforms:
        p_name = p.get("platform", "")
        if p_name in PLATFORM_CLEANUP_DIRECTORIES:
            info = PLATFORM_CLEANUP_DIRECTORIES[p_name]
            account_guides.append({
                "platform": p_name,
                "profile_url": p.get("url", ""),
                "delete_url": info["delete_url"],
                "instructions": info["instructions"],
                "instructions_de": info.get("instructions_de", info["instructions"]),
                "match_score": p.get("match", {}).get("score", 0)
            })

    brokers = []
    if name:
        for b in DATA_BROKERS:
            clean_n = name.strip().replace(" ", "+")
            brokers.append({
                "name": b["name"],
                "search_url": b["search_url_template"].format(clean_n),
                "opt_out_url": b["opt_out_url"],
                "desc": b["desc"],
                "desc_de": b.get("desc_de", b["desc"]),
                "action": b["action"],
                "action_de": b.get("action_de", b["action"])
            })

    return {
        "account_guides": account_guides,
        "data_brokers": brokers
    }
