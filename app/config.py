import os

def load_dotenv():
    """Automatically loads key-value pairs from .env files if present."""
    candidate_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        os.path.join(os.getcwd(), ".env"),
        "/opt/digital-footprint-scanner/.env",
        "/opt/Digital-Footprint-Scanner/.env",
        "/opt/selfscanner/.env",
        "/opt/Selfscanner/.env",
        os.path.expanduser("~/digital-footprint-scanner/.env"),
        os.path.expanduser("~/Digital-Footprint-Scanner/.env"),
    ]
    for env_path in candidate_paths:
        if os.path.isfile(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[7:].strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip()
                            if (v.startswith('"') and '"' in v[1:]) or (v.startswith("'") and "'" in v[1:]):
                                q = v[0]
                                v = v[1:v.find(q, 1)]
                            else:
                                if " #" in v:
                                    v = v.split(" #", 1)[0].strip()
                                v = v.strip().strip("'\"")
                            if k and v:
                                os.environ[k] = v
            except Exception:
                pass

load_dotenv()

class AppSettings:
    app_name: str = "Digital Footprint Scanner - All-in-One OSINT Suite"
    version: str = "1.0.0"

    @property
    def debug(self) -> bool:
        return os.getenv("DEBUG", "false").lower() == "true"

    @property
    def hibp_api_key(self) -> str:
        load_dotenv()
        return os.getenv("HIBP_API_KEY", "")

    @hibp_api_key.setter
    def hibp_api_key(self, val: str):
        os.environ["HIBP_API_KEY"] = val or ""

    @property
    def google_search_api_key(self) -> str:
        load_dotenv()
        return os.getenv("GOOGLE_SEARCH_API_KEY", "")

    @google_search_api_key.setter
    def google_search_api_key(self, val: str):
        os.environ["GOOGLE_SEARCH_API_KEY"] = val or ""

    @property
    def google_search_cx(self) -> str:
        load_dotenv()
        return os.getenv("GOOGLE_SEARCH_CX", "")

    @google_search_cx.setter
    def google_search_cx(self, val: str):
        os.environ["GOOGLE_SEARCH_CX"] = val or ""

    @property
    def google_client_id(self) -> str:
        load_dotenv()
        return os.getenv("GOOGLE_CLIENT_ID", "")

    @property
    def google_client_secret(self) -> str:
        load_dotenv()
        return os.getenv("GOOGLE_CLIENT_SECRET", "")

    @property
    def github_client_id(self) -> str:
        load_dotenv()
        return os.getenv("GITHUB_CLIENT_ID", "")

    @property
    def github_client_secret(self) -> str:
        load_dotenv()
        return os.getenv("GITHUB_CLIENT_SECRET", "")

    @property
    def app_base_url(self) -> str:
        load_dotenv()
        return os.getenv("APP_BASE_URL", "https://footprint.schellenberger.biz")

    @property
    def admin_email(self) -> str:
        load_dotenv()
        return os.getenv("ADMIN_EMAIL", "michael@schellenberger.biz")

settings = AppSettings()
