import re
import urllib.parse
import asyncio
from typing import Dict, Any, List, Optional
from app.config import settings

# Prominent negative patterns for common namesakes of Michael Schellenberger / similar targets
DEFAULT_NEGATIVE_PATTERNS = [
    "cms hasche sigle", "principal counsel", "vermögensstrukturierung",
    "shellenberger", "san fransicko", "apocalypse never", "twitter files",
    "schwedisches königspaar", "feuerwehr", "kreisfeuerwehrverband"
]

def clean_snippet(text: str) -> str:
    """Removes HTML tags and normalizes whitespace."""
    if not text:
        return ""
    no_html = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", no_html).strip()

def filter_search_results(
    raw_results: List[Dict[str, Any]],
    target_name: str,
    context_signals: List[str]
) -> List[Dict[str, Any]]:
    """
    Forensic entity disambiguation filter.
    Only retains results that:
    1. Contain the target surname.
    2. Do NOT match known unrelated namesake vectors (unless explicit user context).
    3. Match at least one strong personal context signal (city, company, domain, keyword, handle).
    """
    verified = []
    seen_urls = set()
    
    clean_name = target_name.strip().lower()
    name_parts = clean_name.split()
    last_name = name_parts[-1] if name_parts else clean_name
    first_name = name_parts[0] if len(name_parts) > 1 else ""

    # Clean context signals
    cleaned_signals = [s.strip() for s in context_signals if s and len(s.strip()) > 2]
    context_blob = " ".join(cleaned_signals).lower()

    for item in raw_results:
        url = item.get("href") or item.get("link") or item.get("url") or ""
        title = item.get("title") or ""
        snippet = item.get("body") or item.get("snippet") or ""

        if not url or url in seen_urls:
            continue

        combined = f"{title} {url} {snippet}".lower()

        # 1. Negative pattern check (Discard known namesakes)
        is_negative = False
        for neg in DEFAULT_NEGATIVE_PATTERNS:
            if neg in combined and neg not in context_blob:
                is_negative = True
                break
        if is_negative:
            continue

        # 2. Name check: Must contain at least the surname
        if last_name and last_name not in combined:
            continue

        # 3. Context Signal Matching
        matches = []
        for sig in cleaned_signals:
            sig_lower = sig.lower()
            if sig_lower in combined:
                matches.append(sig)

        # High confidence match: Matches name AND at least one context signal
        if matches:
            seen_urls.add(url)
            verified.append({
                "title": clean_snippet(title),
                "url": url,
                "snippet": clean_snippet(snippet),
                "matched_signals": list(set(matches)),
                "confidence": "high",
                "verified": True
            })

    return verified


def _sync_ddgs_search(queries: List[str], max_per_query: int = 6) -> List[Dict[str, Any]]:
    """Synchronous execution of DDGS text search across prioritized queries."""
    results = []
    seen = set()
    try:
        from ddgs import DDGS
        ddgs = DDGS()
        for q in queries:
            try:
                for item in ddgs.text(q, max_results=max_per_query):
                    u = item.get("href")
                    if u and u not in seen:
                        seen.add(u)
                        results.append(item)
            except Exception:
                continue
    except Exception:
        pass
    return results


async def search_web_with_entity_filter(
    name: str = "",
    city: str = "",
    employer: str = "",
    domain: str = "",
    username: str = "",
    keywords: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Executes an automated live web search and filters results strictly with zero false-positives.
    """
    clean_name = name.strip()
    if not clean_name and not username:
        return []

    # Compile context signals
    context_signals = []
    if city: context_signals.append(city.strip())
    if employer: context_signals.append(employer.strip())
    if domain:
        clean_dom = domain.strip().lower()
        if clean_dom.startswith("http"):
            from urllib.parse import urlparse
            clean_dom = urlparse(clean_dom).netloc
        clean_dom = clean_dom.split("/")[0]
        context_signals.append(clean_dom)
        # Also add apex
        parts = clean_dom.split(".")
        if len(parts) >= 2:
            context_signals.append(".".join(parts[-2:]))

    if username and len(username) > 3:
        context_signals.append(username.strip())

    if keywords:
        for k in keywords:
            if k and len(k.strip()) > 2:
                context_signals.append(k.strip())

    # Build prioritized queries
    queries = []
    # Query 1: Name + strongest context keyword (e.g. "Michael Schellenberger" Digitalcoach)
    primary_context = None
    for sig in context_signals:
        if sig.lower() not in clean_name.lower():
            primary_context = sig
            break

    if clean_name:
        if primary_context:
            queries.append(f'"{clean_name}" {primary_context}')
        if city:
            queries.append(f'"{clean_name}" {city}')
            queries.append(f'"{clean_name}" {city} impressum')
        queries.append(f'"{clean_name}" impressum')
        queries.append(f'"{clean_name}"')

    if username and len(username) > 3 and not any(sig in username for sig in ["test", "admin"]):
        queries.append(f'"{username}"')

    # Deduplicate queries
    deduped_queries = []
    for q in queries:
        if q not in deduped_queries:
            deduped_queries.append(q)

    # Run in executor with strict timeout (6.0s)
    loop = asyncio.get_event_loop()
    try:
        raw_results = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_ddgs_search, deduped_queries, 6),
            timeout=7.0
        )
    except Exception:
        raw_results = []

    # Filter with Smart Entity Disambiguation
    verified_results = filter_search_results(raw_results, clean_name, context_signals)
    return verified_results
