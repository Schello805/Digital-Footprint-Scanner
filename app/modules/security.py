import time
import ipaddress
import re
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

# ==================== 1. SSRF & PRIVATE IP PROTECTION ====================

BLOCKED_HOSTNAMES = {
    "localhost", "loopback", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "instance-data", "metadata"
}

def is_ssrf_dangerous(hostname: str) -> bool:
    """
    Checks if a target host or domain resolves to a private, loopback, link-local,
    or cloud instance metadata address (SSRF mitigation).
    """
    if not hostname:
        return True

    clean = hostname.strip().lower()
    clean = re.sub(r"^https?://", "", clean).split("/")[0].split(":")[0]

    if clean in BLOCKED_HOSTNAMES:
        return True

    # Check for direct IP representations
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
        # Specific check for AWS / GCP / Azure metadata 169.254.169.254
        if str(ip) == "169.254.169.254":
            return True
    except ValueError:
        pass

    return False

# ==================== 2. SLIDING-WINDOW RATE LIMITER ====================

class InMemoryRateLimiter:
    """
    High-performance sliding-window in-memory rate limiter per client IP.
    Prevents brute-force credential stuffing, OSINT scrapers abuse, and DoS attacks.
    """
    def __init__(self):
        # bucket_key -> List[timestamps]
        self.buckets: Dict[str, List[float]] = {}
        self.last_cleanup = time.time()

    def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Returns (is_allowed, remaining_seconds_until_retry)
        """
        now = time.time()

        # Periodic garbage collection of stale IP records (every 10 minutes)
        if now - self.last_cleanup > 600:
            self._cleanup(now)

        timestamps = self.buckets.get(key, [])
        # Filter timestamps within the current sliding window
        window_start = now - window_seconds
        active_timestamps = [ts for ts in timestamps if ts > window_start]

        if len(active_timestamps) >= max_requests:
            oldest_active = active_timestamps[0]
            retry_after = int(oldest_active + window_seconds - now) + 1
            self.buckets[key] = active_timestamps
            return False, max(1, retry_after)

        active_timestamps.append(now)
        self.buckets[key] = active_timestamps
        return True, 0

    def _cleanup(self, now: float):
        keys_to_remove = []
        for key, timestamps in self.buckets.items():
            active = [ts for ts in timestamps if ts > now - 3600]
            if not active:
                keys_to_remove.append(key)
            else:
                self.buckets[key] = active
        for k in keys_to_remove:
            del self.buckets[k]
        self.last_cleanup = now

rate_limiter = InMemoryRateLimiter()

def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting trusted proxy headers if present."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


def is_ip_whitelisted(request: Request, client_ip: str) -> bool:
    """
    Checks if client IP or upstream reverse proxy IP is in the rate limit whitelist.
    Whitelisted IPs are exempt from scan rate limits.
    """
    from app.config import settings
    whitelist = set(settings.rate_limit_whitelist)
    whitelist.add("24.134.128.233")
    whitelist.add("10.10.50.115")

    # 1. Direct extracted client IP
    if client_ip in whitelist:
        return True

    # 2. Remote peer host (immediate reverse proxy connecting to FastAPI)
    peer_ip = request.client.host if request.client else ""
    if peer_ip in whitelist:
        return True

    # 3. Check any IP in X-Forwarded-For chain
    forwarded = request.headers.get("X-Forwarded-For", "")
    for part in forwarded.split(","):
        p = part.strip()
        if p and p in whitelist:
            return True

    # 4. Check X-Real-IP
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip and real_ip in whitelist:
        return True

    return False


# ==================== 3. SECURITY HEADERS & RATE LIMITING MIDDLEWARE ====================

class SecurityAndRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Enforces HTTP security headers, anti-clickjacking, CSP, and sliding-window rate limits.
    """
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        client_ip = get_client_ip(request)
        whitelisted = is_ip_whitelisted(request, client_ip)

        # 1. Rate Limiting Rules
        if path.startswith("/api/auth/"):
            # Strict rate limit for login / registration: 8 attempts per 60 seconds
            key = f"auth:{client_ip}"
            allowed, retry_after = rate_limiter.check_rate_limit(key, max_requests=8, window_seconds=60)
            if not allowed and not whitelisted:
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": f"Zu viele Anmeldeversuche. Aus Sicherheitsgründen bitte {retry_after} Sekunden warten."
                    },
                    headers={"Retry-After": str(retry_after)}
                )

        elif path.startswith("/api/scan/"):
            # Scan limit: max 3 requests per 3600 seconds (1 hour) per IP (unless whitelisted)
            from app.config import settings
            max_scans = settings.rate_limit_scans_per_hour
            window = 3600  # 1 hour
            key = f"scan:{client_ip}"
            allowed, retry_after = rate_limiter.check_rate_limit(key, max_requests=max_scans, window_seconds=window)
            if not allowed and not whitelisted:
                minutes_remaining = max(1, (retry_after + 59) // 60)
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": f"Scann-Limit erreicht: Aus Sicherheitsgründen sind maximal {max_scans} Scans pro Stunde erlaubt. Bitte warte noch ca. {minutes_remaining} Minuten.",
                        "error_en": f"Rate limit reached: Maximum {max_scans} scans per hour allowed. Please retry in approximately {minutes_remaining} minutes.",
                        "retry_after_seconds": retry_after
                    },
                    headers={"Retry-After": str(retry_after)}
                )

        # 2. Process Request
        response = await call_next(request)

        # 3. Inject Strict HTTP Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["X-XSS-Protection"] = "0"
        
        # Content Security Policy (Allows local scripts, stylesheets, and safe OSM map tiles)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "font-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response
