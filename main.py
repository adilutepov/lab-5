import os
from typing import Optional
from fastapi import FastAPI, Request, Response, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from cryptography.exceptions import InvalidTag

import crypto_service
import auth_service

app = FastAPI(
    title="Academic Crypto Portal",
    description="Interactive Cryptography Demonstration Portal for Lab #5 & Lab #6",
    version="1.0.0"
)

# Setup Templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# ==============================================================================
# Pydantic Request Models for API
# ==============================================================================

class SymmetricEncryptRequest(BaseModel):
    plaintext: str
    password: str
    associated_data: Optional[str] = ""

class SymmetricDecryptRequest(BaseModel):
    ciphertext_hex: str
    tag_hex: str
    nonce_hex: str
    salt_hex: str
    password: str
    associated_data: Optional[str] = ""

class SymmetricDecryptPayloadRequest(BaseModel):
    full_payload_b64: str
    password: str
    associated_data: Optional[str] = ""

class SymmetricTamperRequest(BaseModel):
    ciphertext_hex: str

class AsymmetricSignRequest(BaseModel):
    document_text: str
    private_key_pem: str

class AsymmetricVerifyRequest(BaseModel):
    document_text: str
    signature_hex: str
    public_key_pem: str

class AsymmetricTamperRequest(BaseModel):
    document_text: str

class DemoProfileUpdateRequest(BaseModel):
    username: str
    discipline: str

# ==============================================================================
# Web Interface Routes
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = auth_service.get_current_user(request)
    keycloak_login_url = auth_service.get_keycloak_login_url()
    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "auth_mode": auth_service.AUTH_MODE,
            "keycloak_url": keycloak_login_url,
            "keycloak_server": auth_service.KEYCLOAK_SERVER_URL,
            "keycloak_realm": auth_service.KEYCLOAK_REALM
        }
    )

# ==============================================================================
# Module 1 Endpoints: Symmetric Encryption (AES-256-GCM + PBKDF2)
# ==============================================================================

@app.post("/api/symmetric/encrypt")
async def api_symmetric_encrypt(payload: SymmetricEncryptRequest):
    try:
        result = crypto_service.encrypt_aes_gcm(
            plaintext=payload.plaintext,
            password=payload.password,
            associated_data=payload.associated_data or ""
        )
        return {"success": True, "data": result}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.post("/api/symmetric/decrypt")
async def api_symmetric_decrypt(payload: SymmetricDecryptRequest):
    try:
        decrypted_text = crypto_service.decrypt_aes_gcm(
            ciphertext_hex=payload.ciphertext_hex,
            tag_hex=payload.tag_hex,
            nonce_hex=payload.nonce_hex,
            salt_hex=payload.salt_hex,
            password=payload.password,
            associated_data=payload.associated_data or ""
        )
        return {
            "success": True,
            "decrypted_text": decrypted_text,
            "integrity_verified": True
        }
    except InvalidTag:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "CRITICAL INTEGRITY FAILURE (InvalidTag Exception): "
                         "The ciphertext or authentication tag has been tampered with, "
                         "or an invalid master password was provided! AES-GCM guarantees data integrity."
            }
        )
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.post("/api/symmetric/decrypt-payload")
async def api_symmetric_decrypt_payload(payload: SymmetricDecryptPayloadRequest):
    try:
        decrypted_text = crypto_service.decrypt_payload_b64(
            full_payload_b64=payload.full_payload_b64,
            password=payload.password,
            associated_data=payload.associated_data or ""
        )
        return {
            "success": True,
            "decrypted_text": decrypted_text,
            "integrity_verified": True
        }
    except InvalidTag:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "Integrity Failure (InvalidTag): Invalid password or corrupted payload! AES-GCM authentication tag mismatch."
            }
        )
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.post("/api/symmetric/tamper")
async def api_symmetric_tamper(payload: SymmetricTamperRequest):
    try:
        tampered = crypto_service.tamper_ciphertext(payload.ciphertext_hex)
        return {"success": True, "tampered_ciphertext_hex": tampered}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

# ==============================================================================
# Module 2 Endpoints: Asymmetric Cryptography & Digital Signature (Ed25519)
# ==============================================================================

@app.post("/api/asymmetric/generate-keys")
async def api_asymmetric_generate_keys():
    try:
        keypair = crypto_service.generate_ed25519_keypair()
        return {"success": True, "data": keypair}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.post("/api/asymmetric/sign")
async def api_asymmetric_sign(payload: AsymmetricSignRequest):
    try:
        doc_bytes = payload.document_text.encode("utf-8")
        result = crypto_service.sign_document(doc_bytes, payload.private_key_pem)
        return {"success": True, "data": result}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.post("/api/asymmetric/verify")
async def api_asymmetric_verify(payload: AsymmetricVerifyRequest):
    try:
        doc_bytes = payload.document_text.encode("utf-8")
        result = crypto_service.verify_document_signature(
            doc_bytes,
            payload.signature_hex,
            payload.public_key_pem
        )
        return {"success": True, "data": result}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.post("/api/asymmetric/tamper")
async def api_asymmetric_tamper(payload: AsymmetricTamperRequest):
    try:
        tampered_text = crypto_service.tamper_document_text(payload.document_text)
        return {"success": True, "tampered_text": tampered_text}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

# ==============================================================================
# Lab #6 Auth Foundation Endpoints (Demo Mode & Keycloak Handlers)
# ==============================================================================

@app.post("/api/auth/demo-profile")
async def api_update_demo_profile(payload: DemoProfileUpdateRequest, response: Response):
    auth_service.set_demo_user_cookies(response, payload.username, payload.discipline)
    return {
        "success": True,
        "message": "Demo user attributes updated successfully! Refresh or inspect header badge.",
        "username": payload.username,
        "discipline": payload.discipline
    }

@app.get("/login")
async def login():
    if auth_service.AUTH_MODE == "keycloak_lab6":
        return RedirectResponse(auth_service.get_keycloak_login_url())
    return RedirectResponse("/?info=demo_mode_active")

@app.get("/callback")
async def oidc_callback(code: Optional[str] = None, error: Optional[str] = None):
    if error:
        raise HTTPException(status_code=400, detail=f"OIDC Error: {error}")
    if not code:
        return RedirectResponse("/")
    
    tokens = await auth_service.exchange_code_for_token(code)
    if tokens and "access_token" in tokens:
        response = RedirectResponse("/?auth=success")
        response.set_cookie("access_token", tokens["access_token"], max_age=3600, httponly=True)
        return response
    
    return RedirectResponse("/?auth=failed")

@app.get("/logout")
async def logout(response: Response):
    resp = RedirectResponse("/")
    resp.delete_cookie("access_token")
    resp.delete_cookie("demo_username")
    resp.delete_cookie("demo_discipline")
    return resp
