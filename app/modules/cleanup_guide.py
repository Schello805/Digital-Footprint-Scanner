from typing import Dict, Any, List

PLATFORM_CLEANUP_DIRECTORIES: Dict[str, Dict[str, str]] = {
    "GitHub": {
        "delete_url": "https://github.com/settings/admin",
        "instructions": "Navigiere ganz nach unten zu 'Danger Zone' und klicke auf 'Delete your account'."
    },
    "Reddit": {
        "delete_url": "https://www.reddit.com/settings/account",
        "instructions": "Ganz nach unten scrollen und auf den roten Link 'Account löschen' (Delete account) klicken."
    },
    "Twitter / X": {
        "delete_url": "https://x.com/settings/deactivate",
        "instructions": "Wähle 'Dein Account' -> 'Meinen Account deaktivieren'. Nach 30 Tagen wird das Konto dauerhaft gelöscht."
    },
    "Medium": {
        "delete_url": "https://medium.com/me/settings/security",
        "instructions": "Unter 'Security' ganz nach unten scrollen zu 'Delete account'."
    },
    "Pinterest": {
        "delete_url": "https://www.pinterest.com/settings/account-settings/",
        "instructions": "Klicke ganz unten unter 'Kontoverwaltung' auf 'Konto löschen'."
    },
    "Steam": {
        "delete_url": "https://help.steampowered.com/de/wizard/HelpDeleteAccount",
        "instructions": "Support-Assistenten zur dauerhaften Kontolöschung durchlaufen."
    },
    "Spotify": {
        "delete_url": "https://support.spotify.com/de/article/close-account/",
        "instructions": "Folge dem offiziellen Kündigungs- und Kontoschließungsassistenten."
    },
    "Dev.to": {
        "delete_url": "https://dev.to/settings/misc",
        "instructions": "Ganz unten unter 'Danger Zone' auf 'Delete Account' klicken."
    },
    "GitLab": {
        "delete_url": "https://gitlab.com/-/profile/account",
        "instructions": "Unter 'Delete account' auf den roten Bestätigungs-Button klicken."
    },
    "Gravatar": {
        "delete_url": "https://en.gravatar.com/profiles/edit/#account-deactivation",
        "instructions": "Profil-Avatar entfernen und Deaktivierung auswählen."
    },
    "Linktree": {
        "delete_url": "https://linktr.ee/admin/my-account",
        "instructions": "Unten auf 'Delete account' klicken."
    },
    "About.me": {
        "delete_url": "https://about.me/settings/account",
        "instructions": "Unter Account Settings ganz unten 'Delete your account' wählen."
    },
    "BuyMeACoffee": {
        "delete_url": "https://www.buymeacoffee.com/settings",
        "instructions": "In den Account Settings ganz unten 'Delete account' wählen."
    },
    "Patreon": {
        "delete_url": "https://www.patreon.com/settings/account",
        "instructions": "Unter Kontoeinstellungen ganz unten 'Konto löschen' wählen."
    },
    "Tumblr": {
        "delete_url": "https://www.tumblr.com/settings/account",
        "instructions": "Ganz unten auf 'Account löschen' klicken."
    },
    "Vimeo": {
        "delete_url": "https://vimeo.com/settings/account",
        "instructions": "Unter 'Account' ganz unten 'Delete account' wählen."
    },
    "SoundCloud": {
        "delete_url": "https://soundcloud.com/settings",
        "instructions": "Am Seitenende auf 'Delete account' klicken."
    }
}

DATA_BROKERS_DACH: List[Dict[str, str]] = [
    {
        "name": "Yasni.de (Personensuchmaschine)",
        "search_url_template": "https://www.yasni.de/personensuche/{}",
        "opt_out_url": "https://www.yasni.de/hilfe/eintrag-entfernen",
        "desc": "Aggregiert Webseiten, Foren und Social Accounts unter deinem Klarnamen.",
        "action": "Eintrag auf Yasni aufrufen und über den Feedback-/Entfernen-Button löschen lassen."
    },
    {
        "name": "Das Örtliche & Das Telefonbuch",
        "search_url_template": "https://www.dasoertliche.de/?kw={}",
        "opt_out_url": "https://www.dastelefonbuch.de/service/austragung",
        "desc": "Öffentliche Festnetz- und Mobilfunkverzeichnisse mit Anschriften.",
        "action": "Austragungsantrag beim eigenen Telefonanbieter oder direkt beim Verzeichnisdienst stellen."
    },
    {
        "name": "11880.com (Auskunft & Verzeichnis)",
        "search_url_template": "https://www.11880.com/suche/{}",
        "opt_out_url": "https://www.11880.com/datenschutz",
        "desc": "Telefon- und Branchenverzeichnis mit Adressdaten.",
        "action": "Widerspruch gegen Veröffentlichung per Mail an datenschutz@11880.com."
    },
    {
        "name": "Radaris / PeekYou (Internationale Personensuchmaschinen)",
        "search_url_template": "https://radaris.com/p/{}/",
        "opt_out_url": "https://radaris.com/control/result",
        "desc": "US- und weltweite Aggregatoren für E-Mails, Wohnsitze und Telefonnummern.",
        "action": "Profil aufrufen und den offiziellen Radaris Removal Link nutzen."
    }
]

def get_remediation_guide(found_platforms: List[Dict[str, Any]], name: str = "", email: str = "") -> Dict[str, Any]:
    """
    Inspired by FootprintIQ's LENSiQ cleanup workflow:
    Produces concrete, actionable deactivation steps, direct opt-out links for data brokers,
    and a prioritized digital hygiene checklist.
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
                "match_score": p.get("match", {}).get("score", 0)
            })

    # Data brokers customized with name
    brokers = []
    if name:
        for b in DATA_BROKERS_DACH:
            clean_n = name.strip().replace(" ", "+")
            brokers.append({
                "name": b["name"],
                "search_url": b["search_url_template"].format(clean_n),
                "opt_out_url": b["opt_out_url"],
                "desc": b["desc"],
                "action": b["action"]
            })

    return {
        "account_guides": account_guides,
        "data_brokers": brokers
    }
