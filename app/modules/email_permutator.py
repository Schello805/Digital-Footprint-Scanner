import re
from typing import List, Dict, Any

COMMON_DOMAINS = [
    "gmail.com",
    "gmx.de",
    "web.de",
    "outlook.com",
    "t-online.de",
    "icloud.com",
    "yahoo.de"
]

def generate_email_permutations(first_name: str, last_name: str, custom_domain: str = "") -> List[str]:
    """
    Generates realistic corporate and personal email variations.
    e.g. max.mustermann@..., mmustermann@..., max@...
    """
    fn = re.sub(r'[^a-zA-Z0-9]', '', first_name.strip().lower())
    ln = re.sub(r'[^a-zA-Z0-9]', '', last_name.strip().lower())
    
    if not fn and not ln:
        return []
        
    patterns = []
    
    if fn and ln:
        patterns.extend([
            f"{fn}.{ln}",       # max.mustermann
            f"{fn}{ln}",        # maxmustermann
            f"{fn[0]}.{ln}",     # m.mustermann
            f"{fn[0]}{ln}",      # mmustermann
            f"{fn}_{ln}",       # max_mustermann
            f"{ln}.{fn}",       # mustermann.max
            f"{fn}.{ln[0]}",     # max.m
            f"{fn}{ln[0]}",      # maxm
        ])
    elif fn:
        patterns.append(fn)
    elif ln:
        patterns.append(ln)

    domains = []
    if custom_domain:
        cd = custom_domain.strip().lower()
        cd = re.sub(r'^https?://', '', cd).split('/')[0]
        if cd:
            domains.append(cd)

    # Add top public providers
    domains.extend(COMMON_DOMAINS)
    
    # Deduplicate domains
    seen_domains = set()
    unique_domains = []
    for d in domains:
        if d not in seen_domains:
            seen_domains.add(d)
            unique_domains.append(d)

    permutations = []
    for pat in patterns:
        for dom in unique_domains:
            permutations.append(f"{pat}@{dom}")

    return permutations
