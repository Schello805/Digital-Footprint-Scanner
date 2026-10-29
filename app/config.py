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

settings = AppSettings()
