# concord_logic/config.py
import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, '.env'))

class Config:
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    
    # --- Load All Three Keys Separately ---
    # Key for Flask Sessions
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    
    # Key for HushhMCP Token Signing
    HUSHH_SECRET_KEY = os.getenv("SECRET_KEY")
    
    # Key for HushhMCP Vault Encryption
    VAULT_ENCRYPTION_KEY = os.getenv("VAULT_ENCRYPTION_KEY")
    
    # Google settings
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    
    # A check to make sure all critical keys are loaded
    if not all([SECRET_KEY, HUSHH_SECRET_KEY, VAULT_ENCRYPTION_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET]):
        raise ValueError("One or more critical environment variables are missing. Check your .env file.")
    
    # --- URL and Cookie settings (no change here) ---
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    SERVER_NAME = os.getenv("SERVER_NAME") or None
    
    if SERVER_NAME and "http" not in SERVER_NAME:
        protocol = "https" if ENVIRONMENT == "production" else "http"
        BACKEND_URL_ROOT = f"{protocol}://{SERVER_NAME}"
    else:
        BACKEND_URL_ROOT = SERVER_NAME if SERVER_NAME else "http://localhost:5000"

    GOOGLE_REDIRECT_URI = f"{BACKEND_URL_ROOT}/api/oauth-callback/google"
    
    SESSION_COOKIE_SAMESITE = 'None'
    SESSION_COOKIE_SECURE = False