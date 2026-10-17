import os
import json
import base64
import urllib.parse
from typing import Dict, Any, Optional
from fastapi import Request, Response
from dotenv import load_dotenv

load_dotenv()

# Configuration
AUTH_MODE = os.getenv("AUTH_MODE", "demo_lab5")
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key_123")
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://localhost:8080").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "crypto-portal")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
KEYCLOAK_REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI", "http://localhost:8000/callback")
KEYCLOAK_SCOPE = os.getenv("KEYCLOAK_SCOPE", "openid discipline")

# Default demo session state for Lab #5
DEFAULT_DEMO_USER = {
    "username": "alice_crypto_researcher",
    "email": "alice.crypto@university.edu",
    "role": "Lab Specialist",
    "discipline": "Cybersecurity & Defensive Coding",
    "auth_source": "Local Demo Session (Lab #5)"
}

def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Resolves the active user profile.
    In 'demo_lab5' mode: reads from cookies or falls back to editable demo defaults.
    In 'keycloak_lab6' mode: inspects Authorization header or session token from Keycloak.
    """
    if AUTH_MODE == "keycloak_lab6":
        token = request.cookies.get("access_token")
        if token:
            payload = decode_keycloak_token(token)
            if payload:
                return {
                    "username": payload.get("preferred_username", "keycloak_user"),
                    "email": payload.get("email", "user@keycloak.local"),
                    "role": "Keycloak Authenticated User",
                    "discipline": payload.get("discipline", "Not specified in token"),
                    "auth_source": f"Keycloak OIDC Realm: {KEYCLOAK_REALM}"
                }
        return {
            "username": "Anonymous (Unauthenticated)",
            "email": "none",
            "role": "Guest",
            "discipline": "Guest Mode",
            "auth_source": "Keycloak Required (Lab #6)"
        }
    
    # demo_lab5 mode: check demo cookies
    demo_username = request.cookies.get("demo_username", DEFAULT_DEMO_USER["username"])
    demo_discipline = request.cookies.get("demo_discipline", DEFAULT_DEMO_USER["discipline"])
    
    return {
        "username": demo_username,
        "email": f"{demo_username.lower().replace(' ', '_')}@crypto-portal.edu",
        "role": DEFAULT_DEMO_USER["role"],
        "discipline": demo_discipline,
        "auth_source": "Autonomous Lab #5 Mode"
    }

def set_demo_user_cookies(response: Response, username: str, discipline: str):
    """Saves user modifications to cookies in demo mode."""
    response.set_cookie("demo_username", username, max_age=86400, httponly=True)
    response.set_cookie("demo_discipline", discipline, max_age=86400, httponly=True)

# ==============================================================================
# Foundation for Lab #6: Keycloak OAuth2.0 / OpenID Connect (OIDC)
# ==============================================================================

def get_keycloak_login_url() -> str:
    """Constructs the Keycloak Authorization URL for Lab #6."""
    auth_endpoint = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": KEYCLOAK_SCOPE,
        "redirect_uri": KEYCLOAK_REDIRECT_URI,
        "state": "crypto_portal_security_state_seed"
    }
    return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

async def exchange_code_for_token(code: str) -> Optional[Dict[str, Any]]:
    """Exchanges authorization code for tokens at Keycloak token endpoint."""
    token_endpoint = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": KEYCLOAK_REDIRECT_URI
    }
    try:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(token_endpoint, data=data)
                if resp.status_code == 200:
                    return resp.json()
        except ImportError:
            import requests
            resp = requests.post(token_endpoint, data=data, timeout=10)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"[Keycloak Auth Error] Failed to contact Keycloak: {e}")
    return None

def decode_keycloak_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes JWT payload. Supports PyJWT if installed, or standard base64 url-safe parser."""
    try:
        try:
            import jwt
            return jwt.decode(token, options={"verify_signature": False})
        except ImportError:
            # Fallback: pure standard library base64 decode of JWT payload part
            parts = token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1]
                # Pad base64 if needed
                payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                decoded_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
                return json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        print(f"[JWT Decode Error]: {e}")
    return None
