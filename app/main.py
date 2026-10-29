import json
import asyncio
import secrets
import urllib.parse
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, Response, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.config import settings
from app.modules.username_checker import scan_username_stream
from app.modules.exif_inspector import extract_exif_metadata, strip_exif_metadata
from app.modules.domain_recon import check_domain_dns
from app.modules.breach_checker import check_password_pwned, check_email_breach
from app.modules.dork_builder import generate_dorks
from app.modules.email_permutator import generate_email_permutations
from app.modules.phone_recon import analyze_phone_number
from app.modules.mailing_list_checker import check_mailing_lists
from app.modules.identity_auditor import audit_identity_profile
from app.modules.full_scanner import execute_full_scan
from app.modules.unsubscribe_hub import generate_unsubscribe_package, generate_batch_broker_optout_package, MARKETING_LIST_BROKERS

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Automatisierter Digital Footprint & OSINT Privacy Auditor"
)

# Cybersecurity Hardening: Enforce Security Headers, CSP & Rate Limiting
from app.modules.security import SecurityAndRateLimitMiddleware
app.add_middleware(SecurityAndRateLimitMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    return FileResponse("app/static/img/favicon.ico")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("app/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()

# --- Helper: User Session Resolution ---
def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
    if not token:
        token = request.cookies.get("session_token")
    if token:
        from app.modules.db import get_user_from_token
        user = get_user_from_token(token)
        if user:
            admin_target = settings.admin_email.strip().lower()
            user["is_admin"] = bool((admin_target and user["email"].lower() == admin_target) or user["id"] == 1)
            return user
    return None

# --- 0. Full Footprint 1-Click Scan ---
class FullScanRequest(BaseModel):
    name: Optional[str] = ""
    username: Optional[str] = ""
    email: Optional[str] = ""
    password: Optional[str] = ""
    domain: Optional[str] = ""
    phone: Optional[str] = ""
    city: Optional[str] = ""
    employer: Optional[str] = ""
    keywords: Optional[str] = ""

@app.post("/api/scan/full")
async def full_scan(req: FullScanRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Zugriff verweigert: Bitte registriere dich oder melde dich an, um deinen digitalen Fußabdruck zu scannen."
        )
    result = await execute_full_scan(req.dict())
    from app.modules.db import save_user_scan
    scan_id = save_user_scan(user["id"], req.dict(), result)
    result["saved_scan_id"] = scan_id
    result["user_email"] = user["email"]
    return result

# --- 1. Username Scanner with Context & Bio Matching (SSE Stream) ---
@app.get("/api/scan/username/stream")
async def stream_username_scan(
    username: str = Query(..., min_length=2, max_length=50),
    name: Optional[str] = Query(None),
    city: Optional[str] = Query(None),
    employer: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None)
):
    context = None
    if name or city or employer or keywords:
        kw_list = [k.strip() for k in keywords.split(",")] if keywords else []
        context = {
            "name": name or "",
            "city": city or "",
            "employer": employer or "",
            "keywords": kw_list
        }

    async def event_generator():
        try:
            async for hit in scan_username_stream(username, context=context):
                yield f"data: {json.dumps(hit)}\n\n"
            yield f"data: {json.dumps({'event': 'done', 'username': username})}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# --- 2. Identity Multi-Target Audit ---
class IdentityAuditRequest(BaseModel):
    full_name: Optional[str] = ""
    usernames: Optional[List[str]] = []
    cities: Optional[List[str]] = []
    employers: Optional[List[str]] = []
    emails: Optional[List[str]] = []
    phones: Optional[List[str]] = []
    keywords: Optional[List[str]] = []

@app.post("/api/audit/identity")
async def audit_identity(req: IdentityAuditRequest):
    result = audit_identity_profile(req.dict())
    return result

# --- 3. EXIF & Metadata Inspector ---
MAX_IMAGE_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB limit

@app.post("/api/exif/inspect")
async def inspect_exif(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Keine Datei übermittelt")
    if len(content) > MAX_IMAGE_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Dateigröße überschreitet das Sicherheitslimit von 15 MB.")
    result = extract_exif_metadata(content, filename=file.filename or "upload.jpg")
    return result

@app.post("/api/exif/strip")
async def strip_exif(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Keine Datei übermittelt")
    if len(content) > MAX_IMAGE_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Dateigröße überschreitet das Sicherheitslimit von 15 MB.")
    try:
        clean_bytes, fmt = strip_exif_metadata(content)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    clean_name = f"sanitized_{file.filename or 'image'}"
    if not clean_name.lower().endswith(f".{fmt}"):
        clean_name += f".{fmt}"
    
    media_type = f"image/{fmt}" if fmt != "jpg" else "image/jpeg"
    return Response(
        content=clean_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{clean_name}"'}
    )

# --- 4. Domain & DNS / Mail Spoofing Recon ---
@app.get("/api/recon/domain")
async def recon_domain(domain: str = Query(..., min_length=3)):
    result = check_domain_dns(domain)
    return result

# --- 5. Phone Recon ---
@app.get("/api/recon/phone")
async def recon_phone(phone: str = Query(..., min_length=4)):
    result = analyze_phone_number(phone)
    return {"success": True, "data": result}

# --- 6. Email Permutations ---
@app.get("/api/permutations/email")
async def get_email_permutations(
    first_name: str = Query(...),
    last_name: str = Query(...),
    domain: Optional[str] = Query("")
):
    perms = generate_email_permutations(first_name, last_name, custom_domain=domain or "")
    return {"success": True, "data": perms}

# --- 7. Mailing List Recon & Unsubscribe Hub (Incogni-Style) ---
@app.get("/api/recon/mailinglists")
async def recon_mailing_lists(email: str = Query(..., min_length=5)):
    result = await check_mailing_lists(email)
    return result

# --- 6b. Unsubscribe & Opt-Out Hub (Incogni-Style) ---
class UnsubscribeRequest(BaseModel):
    list_identifier: str
    user_email: str
    user_name: Optional[str] = ""
    lang: Optional[str] = "en"

@app.post("/api/unsubscribe/generate")
async def api_generate_unsubscribe(req: UnsubscribeRequest):
    if not req.list_identifier or not req.user_email:
        raise HTTPException(status_code=400, detail="Mailingliste und E-Mail-Adresse erforderlich.")
    return generate_unsubscribe_package(
        list_identifier=req.list_identifier,
        user_email=req.user_email,
        user_name=req.user_name or "",
        lang=req.lang or "en"
    )

@app.get("/api/unsubscribe/brokers")
async def api_get_marketing_brokers():
    return {"success": True, "data": MARKETING_LIST_BROKERS, "brokers": MARKETING_LIST_BROKERS}

class BatchBrokerOptOutRequest(BaseModel):
    user_email: str
    user_name: Optional[str] = ""
    user_phone: Optional[str] = ""
    user_city: Optional[str] = ""
    lang: Optional[str] = "en"

@app.post("/api/unsubscribe/batch-brokers")
async def api_generate_batch_brokers(req: BatchBrokerOptOutRequest):
    if not req.user_email:
        raise HTTPException(status_code=400, detail="E-Mail-Adresse erforderlich.")
    return generate_batch_broker_optout_package(
        user_email=req.user_email,
        user_name=req.user_name or "",
        user_phone=req.user_phone or "",
        user_city=req.user_city or "",
        lang=req.lang or "en"
    )

# --- 7. Breach Checkers ---
class PasswordCheckRequest(BaseModel):
    password: str

@app.post("/api/breach/password")
async def check_password(req: PasswordCheckRequest):
    result = await check_password_pwned(req.password)
    return result

@app.get("/api/breach/email")
async def check_email(email: str = Query(...)):
    result = await check_email_breach(email, api_key=settings.hibp_api_key)
    return result

# --- 8. Google Dorking Generator ---
class DorkRequest(BaseModel):
    name: Optional[str] = ""
    city: Optional[str] = ""
    company: Optional[str] = ""
    username: Optional[str] = ""
    email: Optional[str] = ""

@app.post("/api/dorks/generate")
async def create_dorks(req: DorkRequest):
    results = generate_dorks(
        name=req.name or "",
        city=req.city or "",
        company=req.company or "",
        username=req.username or "",
        email=req.email or ""
    )
    return {"success": True, "data": results}

# --- 9. Settings ---
class SettingsUpdate(BaseModel):
    hibp_api_key: Optional[str] = None
    google_search_api_key: Optional[str] = None
    google_search_cx: Optional[str] = None

@app.get("/api/settings")
async def get_settings(request: Request):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Zugriff verweigert: Nur der Administrator kann API-Keys und Server-Einstellungen einsehen.")
    return {
        "hibp_api_key_configured": bool(settings.hibp_api_key),
        "google_search_configured": bool(settings.google_search_api_key and settings.google_search_cx),
        "google_oauth_configured": bool(settings.google_client_id),
        "github_oauth_configured": bool(settings.github_client_id)
    }

@app.post("/api/settings")
async def update_settings(update: SettingsUpdate, request: Request):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Zugriff verweigert: Nur der Administrator kann Systemeinstellungen ändern.")
    if update.hibp_api_key is not None:
        settings.hibp_api_key = update.hibp_api_key.strip()
    if update.google_search_api_key is not None:
        settings.google_search_api_key = update.google_search_api_key.strip()
    if update.google_search_cx is not None:
        settings.google_search_cx = update.google_search_cx.strip()
    return {"success": True, "message": "Einstellungen erfolgreich aktualisiert."}

# --- 10. System Version & Update Check ---
from app.modules.version_tracker import check_for_updates

@app.get("/api/system/version")
async def get_system_version():
    """
    Returns current local git revision, commit hash, and checks GitHub for upstream updates.
    """
    version_info = await check_for_updates()
    return {"success": True, "data": version_info}

# --- 11. Multi-User Authentication & Personal Scans ---
class AuthRequest(BaseModel):
    email: str
    password: str

@app.post("/api/auth/register")
async def api_register(req: AuthRequest, request: Request, response: Response):
    from app.modules.db import register_user
    user, token, err = register_user(req.email, req.password)
    if err:
        return {"success": False, "error": err}
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        "session_token", token, max_age=30*86400, httponly=True, secure=is_https, samesite="lax", path="/"
    )
    return {"success": True, "user": user, "token": token}

@app.post("/api/auth/login")
async def api_login(req: AuthRequest, request: Request, response: Response):
    from app.modules.db import login_user
    user, token, err = login_user(req.email, req.password)
    if err:
        return {"success": False, "error": err}
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        "session_token", token, max_age=30*86400, httponly=True, secure=is_https, samesite="lax", path="/"
    )
    return {"success": True, "user": user, "token": token}

@app.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    from app.modules.db import logout_token
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
    if not token:
        token = request.cookies.get("session_token")
    if token:
        logout_token(token)
    response.delete_cookie("session_token")
    return {"success": True}

@app.get("/api/auth/me")
async def api_me(request: Request):
    user = get_current_user(request)
    if user:
        return {"success": True, "authenticated": True, "user": user}
    return {"success": True, "authenticated": False, "user": None}

def get_app_base_url(request: Request) -> str:
    if settings.app_base_url:
        return settings.app_base_url.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    return f"{proto}://{host}"

# --- Google OAuth 2.0 ---
@app.get("/api/auth/oauth/google/login")
async def oauth_google_login(request: Request):
    if not settings.google_client_id:
        return HTMLResponse(
            f"""
            <html><head><meta charset="utf-8"><title>Google OAuth Setup</title>
            <body style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#141c2e;color:#e2e8f0;padding:40px;line-height:1.6;">
            <div style="max-width:620px;margin:auto;background:#1a243a;padding:32px;border-radius:18px;border:1px solid #334466;box-shadow:0 20px 40px rgba(0,0,0,0.5);">
              <h2 style="color:#60a5fa;margin-top:0;">⚙️ Google OAuth Konfiguration</h2>
              <p>Um die Google-Anmeldung zu aktivieren, erstelle in der <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color:#38bdf8;text-decoration:underline;">Google Cloud Console</a> eine <b>OAuth-Client-ID</b> und hinterlege diese in der Umgebung oder <code>.env</code>:</p>
              <pre style="background:#0f172a;padding:14px;border-radius:10px;color:#a5f3fc;font-size:12px;border:1px solid #334155;overflow-x:auto;">GOOGLE_CLIENT_ID="deine-id.apps.googleusercontent.com"&#10;GOOGLE_CLIENT_SECRET="dein-secret"</pre>
              <p style="margin-top:16px;"><b>Autorisierte Weiterleitungs-URI (Redirect URI):</b><br>
                <code style="background:#0f172a;padding:6px 10px;border-radius:6px;color:#34d399;font-size:13px;display:inline-block;margin-top:4px;word-break:break-all;">{get_app_base_url(request)}/api/auth/oauth/google/callback</code>
              </p>
              <div style="margin-top:28px;"><a href="/" style="background:#4f46e5;color:#fff;padding:10px 20px;border-radius:10px;text-decoration:none;font-weight:bold;display:inline-block;">← Zurück zur App</a></div>
            </div>
            </body></html>
            """,
            status_code=200
        )
    
    redirect_uri = f"{get_app_base_url(request)}/api/auth/oauth/google/callback"
    state = secrets.token_urlsafe(16)
    google_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={urllib.parse.quote(settings.google_client_id)}&"
        f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        f"state={state}"
    )
    return RedirectResponse(google_url)

@app.get("/api/auth/oauth/google/callback")
async def oauth_google_callback(request: Request, code: Optional[str] = None, error: Optional[str] = None):
    if error or not code:
        return RedirectResponse("/?oauth_error=" + (error or "missing_code"))
    
    import httpx
    redirect_uri = f"{get_app_base_url(request)}/api/auth/oauth/google/callback"
    try:
        async with httpx.AsyncClient() as http_client:
            token_resp = await http_client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                timeout=10.0
            )
            tokens = token_resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                return RedirectResponse("/?oauth_error=token_exchange_failed")
            
            userinfo_resp = await http_client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0
            )
            user_info = userinfo_resp.json()
            email = user_info.get("email")
            if not email:
                return RedirectResponse("/?oauth_error=no_email")
            
            name = user_info.get("name") or f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}".strip()
            picture = user_info.get("picture") or ""

            from app.modules.db import get_or_create_oauth_user
            user, session_token, err = get_or_create_oauth_user(
                email=email, 
                provider="google", 
                oauth_id=str(user_info.get("id", "")),
                name=name,
                avatar_url=picture,
                oauth_data=user_info
            )
            if err:
                return RedirectResponse("/?oauth_error=" + urllib.parse.quote(err))
            
            redirect_url = f"/?auth_token={session_token}&login_success=1"
            response = RedirectResponse(redirect_url, status_code=303)
            is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            response.set_cookie(
                "session_token", session_token, max_age=30*86400, httponly=True, secure=is_https, samesite="lax", path="/"
            )
            return response
    except Exception as e:
        return RedirectResponse("/?oauth_error=" + urllib.parse.quote(str(e)))

# --- GitHub OAuth 2.0 ---
@app.get("/api/auth/oauth/github/login")
async def oauth_github_login(request: Request):
    if not settings.github_client_id:
        return HTMLResponse(
            f"""
            <html><head><meta charset="utf-8"><title>GitHub OAuth Setup</title>
            <body style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#141c2e;color:#e2e8f0;padding:40px;line-height:1.6;">
            <div style="max-width:620px;margin:auto;background:#1a243a;padding:32px;border-radius:18px;border:1px solid #334466;box-shadow:0 20px 40px rgba(0,0,0,0.5);">
              <h2 style="color:#60a5fa;margin-top:0;">⚙️ GitHub OAuth Konfiguration</h2>
              <p>Um die GitHub-Anmeldung zu aktivieren, erstelle in den <a href="https://github.com/settings/developers" target="_blank" style="color:#38bdf8;text-decoration:underline;">GitHub Developer Settings</a> eine <b>OAuth App</b> und hinterlege diese in der Umgebung oder <code>.env</code>:</p>
              <pre style="background:#0f172a;padding:14px;border-radius:10px;color:#a5f3fc;font-size:12px;border:1px solid #334155;overflow-x:auto;">GITHUB_CLIENT_ID="deine-github-client-id"&#10;GITHUB_CLIENT_SECRET="dein-github-secret"</pre>
              <p style="margin-top:16px;"><b>Authorization Callback URL:</b><br>
                <code style="background:#0f172a;padding:6px 10px;border-radius:6px;color:#34d399;font-size:13px;display:inline-block;margin-top:4px;word-break:break-all;">{get_app_base_url(request)}/api/auth/oauth/github/callback</code>
              </p>
              <div style="margin-top:28px;"><a href="/" style="background:#4f46e5;color:#fff;padding:10px 20px;border-radius:10px;text-decoration:none;font-weight:bold;display:inline-block;">← Zurück zur App</a></div>
            </div>
            </body></html>
            """,
            status_code=200
        )
    
    redirect_uri = f"{get_app_base_url(request)}/api/auth/oauth/github/callback"
    state = secrets.token_urlsafe(16)
    github_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={urllib.parse.quote(settings.github_client_id)}&"
        f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
        "scope=user:email&"
        f"state={state}"
    )
    return RedirectResponse(github_url)

@app.get("/api/auth/oauth/github/callback")
async def oauth_github_callback(request: Request, code: Optional[str] = None, error: Optional[str] = None):
    if error or not code:
        return RedirectResponse("/?oauth_error=" + (error or "missing_code"))
    
    import httpx
    redirect_uri = f"{get_app_base_url(request)}/api/auth/oauth/github/callback"
    try:
        async with httpx.AsyncClient() as http_client:
            token_resp = await http_client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                timeout=10.0
            )
            tokens = token_resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                return RedirectResponse("/?oauth_error=github_token_exchange_failed")
            
            user_resp = await http_client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10.0
            )
            user_data = user_resp.json()
            email = user_data.get("email")
            
            if not email:
                emails_resp = await http_client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                    timeout=10.0
                )
                emails = emails_resp.json()
                if isinstance(emails, list):
                    primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
                    if primary:
                        email = primary.get("email")
                    elif len(emails) > 0:
                        email = emails[0].get("email")
            
            if not email:
                return RedirectResponse("/?oauth_error=no_github_verified_email")
            
            from app.modules.db import get_or_create_oauth_user
            name = user_data.get("name") or user_data.get("login") or ""
            avatar = user_data.get("avatar_url") or ""
            user, session_token, err = get_or_create_oauth_user(
                email=email, 
                provider="github", 
                oauth_id=str(user_data.get("id", "")),
                name=name,
                avatar_url=avatar,
                oauth_data=user_data
            )
            if err:
                return RedirectResponse("/?oauth_error=" + urllib.parse.quote(err))
            
            redirect_url = f"/?auth_token={session_token}&login_success=1"
            response = RedirectResponse(redirect_url, status_code=303)
            is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            response.set_cookie(
                "session_token", session_token, max_age=30*86400, httponly=True, secure=is_https, samesite="lax", path="/"
            )
            return response
    except Exception as e:
        return RedirectResponse("/?oauth_error=" + urllib.parse.quote(str(e)))

@app.get("/api/user/scans")
async def api_user_scans(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Bitte anmelden, um gespeicherte Scans einzusehen.")
    from app.modules.db import get_user_scans_list
    scans = get_user_scans_list(user["id"])
    return {"success": True, "scans": scans}

@app.get("/api/user/scans/{scan_id}")
async def api_get_user_scan(scan_id: int, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Bitte anmelden.")
    from app.modules.db import get_scan_by_id
    scan = get_scan_by_id(user["id"], scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden.")
    return {"success": True, "scan": scan}

@app.delete("/api/user/scans/{scan_id}")
async def api_delete_user_scan(scan_id: int, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Bitte anmelden.")
    from app.modules.db import delete_user_scan
    deleted = delete_user_scan(user["id"], scan_id)
    return {"success": deleted}


