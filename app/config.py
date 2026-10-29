import os
from pydantic import BaseModel

class AppSettings(BaseModel):
    app_name: str = "Digital Footprint Scanner - All-in-One OSINT Suite"
    version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Optional API Keys (defaults to None / empty)
    hibp_api_key: str = os.getenv("HIBP_API_KEY", "")
    google_search_api_key: str = os.getenv("GOOGLE_SEARCH_API_KEY", "")
    google_search_cx: str = os.getenv("GOOGLE_SEARCH_CX", "")

    # OAuth 2.0 (Google & GitHub)
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    github_client_id: str = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    app_base_url: str = os.getenv("APP_BASE_URL", "") # e.g. https://footprint.schellenberger.biz

    # Administration
    admin_email: str = os.getenv("ADMIN_EMAIL", "michael@schellenberger.biz")

settings = AppSettings()
