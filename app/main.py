import json
import asyncio
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, Response, FileResponse
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

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    return FileResponse("app/static/img/favicon.ico")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("app/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()

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
async def full_scan(req: FullScanRequest):
    result = await execute_full_scan(req.dict())
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
@app.post("/api/exif/inspect")
async def inspect_exif(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Keine Datei übermittelt")
    result = extract_exif_metadata(content, filename=file.filename or "upload.jpg")
    return result

@app.post("/api/exif/strip")
async def strip_exif(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Keine Datei übermittelt")
    clean_bytes, fmt = strip_exif_metadata(content)
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
async def get_settings():
    return {
        "hibp_api_key_configured": bool(settings.hibp_api_key),
        "google_search_configured": bool(settings.google_search_api_key and settings.google_search_cx)
    }

@app.post("/api/settings")
async def update_settings(update: SettingsUpdate):
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

