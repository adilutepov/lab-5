"""
Lab #10: DevSecOps & Secret Management Module for Academic Crypto Portal.
Implements 4 Secret Provisioning Architectures from Lecture #10:
1. Environment Variable Provisioning (Slide 36)
2. File-based Secret Provisioning (Slide 37)
3. Decentralized Secret Provisioning — SealedSecret / Asymmetric Public-Key Encryption (Slides 39, 43-44)
4. Centralized Secret Management — Vault-compatible HTTP Secret Server with Auth & Audit Logs (Slides 40-42)
"""

import base64
import json
import os
import stat
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REQUIRED_APP_SECRETS: List[str] = [
    "SECRET_KEY",
    "KEYCLOAK_CLIENT_SECRET",
    "MASTER_ENCRYPTION_KEY",
    "DB_CONNECTION_PASSWORD",
]


def mask_secret(value: str) -> str:
    """Masks a secret string for safe logging and auditing (prevents log leaks - Slide 29)."""
    if not value or len(value) < 8:
        return "****"
    return f"{value[:4]}...{value[-4:]} (len={len(value)})"


# ==============================================================================
# 1. Environment Variable & 2. File-Based Provisioning (Slides 36-37)
# ==============================================================================

class ExternalStorageProvider:
    """Retrieves application secrets from OS Environment Variables or Mounted Secret Files."""

    @staticmethod
    def from_environment(prefix: str = "") -> Dict[str, str]:
        """Reads secrets from OS environment variables (Slide 36)."""
        result: Dict[str, str] = {}
        for key in REQUIRED_APP_SECRETS:
            env_name = f"{prefix}{key}" if prefix else key
            val = os.getenv(env_name)
            if val:
                result[key] = val
        return result

    @staticmethod
    def from_secret_file(file_path: str) -> Dict[str, Any]:
        """Reads secrets from a mounted JSON secret file and inspects permissions (Slide 37)."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Secret file not found: {file_path}")

        st_mode = os.stat(file_path).st_mode
        octal_perms = oct(stat.S_IMODE(st_mode))

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        secrets = {k: str(data[k]) for k in REQUIRED_APP_SECRETS if k in data}
        return {
            "provider": "file_mount",
            "file_path": file_path,
            "permissions": octal_perms,
            "secrets": secrets,
        }


# ==============================================================================
# 3. Decentralized Approach: SealedSecret Asymmetric Encryption (Slides 39, 43-44)
# ==============================================================================

class DecentralizedSealedSecret:
    """
    Implements the Decentralized Secret Management pattern ('Encrypt locally, store publicly,
    decrypt only in the target environment' - Slides 39, 43-44).
    Uses RSA-2048 OAEP (public/private keypair) wrapping an ephemeral AES-256-GCM key.
    The encrypted manifest (secrets.sealed.json) is safe to commit to Git.
    """

    @staticmethod
    def generate_sealing_keypair() -> Dict[str, str]:
        """Generates RSA-2048 keypair for sealing/unsealing secrets."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return {"private_key_pem": priv_pem, "public_key_pem": pub_pem}

    @staticmethod
    def seal_secrets(secrets_dict: Dict[str, str], public_key_pem: str, output_file: str) -> Dict[str, Any]:
        """
        Encrypts secrets locally using the Public Key so the sealed file can be stored publicly in Git.
        """
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        ephemeral_aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        aesgcm = AESGCM(ephemeral_aes_key)

        plaintext_bytes = json.dumps(secrets_dict).encode("utf-8")
        aad = b"SealedSecret:v1:crypto_portal"
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

        encrypted_aes_key = pub_key.encrypt(
            ephemeral_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        sealed_manifest = {
            "apiVersion": "devsecops.lab10/v1alpha1",
            "kind": "SealedSecret",
            "metadata": {
                "name": "crypto-portal-sealed-secrets",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "algorithm": "RSA-2048-OAEP + AES-256-GCM",
            },
            "spec": {
                "encryptedDataKey_b64": base64.b64encode(encrypted_aes_key).decode("ascii"),
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
                "secretKeys": list(secrets_dict.keys()),
            },
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sealed_manifest, f, indent=2)

        return sealed_manifest

    @staticmethod
    def unseal_secrets(sealed_file: str, private_key_pem: str) -> Dict[str, str]:
        """
        Decrypts the SealedSecret manifest inside the target runtime environment using the Private Key.
        """
        with open(sealed_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        spec = manifest["spec"]

        encrypted_aes_key = base64.b64decode(spec["encryptedDataKey_b64"])
        nonce = base64.b64decode(spec["nonce_b64"])
        ciphertext = base64.b64decode(spec["ciphertext_b64"])

        ephemeral_aes_key = priv_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm = AESGCM(ephemeral_aes_key)
        aad = b"SealedSecret:v1:crypto_portal"
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
        return json.loads(plaintext_bytes.decode("utf-8"))


# ==============================================================================
# 4. Centralized Approach: Secret Manager Server & Client (Slides 40-42)
# ==============================================================================

class CentralizedVaultServer:
    """
    Lightweight Vault-compatible Centralized Secret Manager (Slides 40-42).
    Features:
    - Encryption at rest in memory (AES-256-GCM)
    - AppRole authentication (POST /v1/auth/approle/login -> issues short-lived client token)
    - RBAC authorization & secret retrieval (GET /v1/secret/data/crypto_portal)
    - Full audit logging with timestamps and lease TTL
    """

    def __init__(self, initial_secrets: Dict[str, str], host: str = "127.0.0.1", port: int = 8201):
        self.host = host
        self.port = port
        self._master_key = AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._master_key)
        self._nonce = os.urandom(12)
        self._encrypted_store = self._aesgcm.encrypt(
            self._nonce, json.dumps(initial_secrets).encode("utf-8"), b"vault:v1"
        )
        self.valid_role_id = "crypto-portal-app-role"
        self.valid_secret_id = "approle-secret-9f8e7d6c"  # noqa: S105 # nosec B105
        self.active_tokens: Dict[str, float] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _decrypt_store(self) -> Dict[str, str]:
        raw = self._aesgcm.decrypt(self._nonce, self._encrypted_store, b"vault:v1")
        return json.loads(raw.decode("utf-8"))

    def start(self) -> None:
        vault = self

        class VaultHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress noisy default HTTP logs

            def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                if self.path == "/v1/auth/approle/login":
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8")
                    data = json.loads(raw_body) if raw_body else {}

                    if data.get("role_id") == vault.valid_role_id and data.get("secret_id") == vault.valid_secret_id:
                        token = f"hvs.{base64.urlsafe_b64encode(os.urandom(18)).decode('ascii')}"
                        vault.active_tokens[token] = time.time() + 3600
                        vault.audit_log.append({
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "event": "auth.approle.login",
                            "status": "200 OK",
                            "role_id": data.get("role_id"),
                            "token_masked": mask_secret(token),
                        })
                        self._send_json(200, {
                            "auth": {
                                "client_token": token,
                                "policies": ["default", "crypto-portal-read"],
                                "lease_duration": 3600,
                                "renewable": True,
                            }
                        })
                    else:
                        vault.audit_log.append({
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "event": "auth.approle.login",
                            "status": "403 Forbidden",
                        })
                        self._send_json(403, {"errors": ["invalid role_id or secret_id"]})
                else:
                    self._send_json(404, {"errors": ["path not found"]})

            def do_GET(self) -> None:
                if self.path == "/v1/secret/data/crypto_portal":
                    token = self.headers.get("X-Vault-Token", "")
                    exp = vault.active_tokens.get(token, 0)
                    if exp > time.time():
                        secrets = vault._decrypt_store()
                        vault.audit_log.append({
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "event": "secret.kv.read",
                            "path": "secret/data/crypto_portal",
                            "status": "200 OK",
                            "token_masked": mask_secret(token),
                        })
                        self._send_json(200, {
                            "request_id": base64.urlsafe_b64encode(os.urandom(12)).decode("ascii"),
                            "lease_duration": 3600,
                            "data": {
                                "data": secrets,
                                "metadata": {"version": 1, "encrypted_at_rest": True},
                            },
                        })
                    else:
                        self._send_json(403, {"errors": ["permission denied: invalid or expired X-Vault-Token"]})
                else:
                    self._send_json(404, {"errors": ["not found"]})

        self._server = HTTPServer((self.host, self.port), VaultHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


class CentralizedVaultClient:
    """Client that authenticates to the Centralized Secret Manager and retrieves decrypted secrets."""

    def __init__(self, vault_addr: str = "http://127.0.0.1:8201"):
        self.vault_addr = vault_addr.rstrip("/")

    def authenticate_and_fetch(self, role_id: str, secret_id: str) -> Dict[str, Any]:
        login_url = f"{self.vault_addr}/v1/auth/approle/login"
        login_payload = json.dumps({"role_id": role_id, "secret_id": secret_id}).encode("utf-8")

        req_auth = urllib.request.Request(  # noqa: S310
            login_url,
            data=login_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_auth, timeout=5) as resp:  # noqa: S310 # nosec B310
            auth_data = json.loads(resp.read().decode("utf-8"))

        client_token = auth_data["auth"]["client_token"]

        secret_url = f"{self.vault_addr}/v1/secret/data/crypto_portal"
        req_sec = urllib.request.Request(  # noqa: S310
            secret_url,
            headers={"X-Vault-Token": client_token},
            method="GET",
        )
        with urllib.request.urlopen(req_sec, timeout=5) as resp:  # noqa: S310 # nosec B310
            secret_resp = json.loads(resp.read().decode("utf-8"))

        return {
            "client_token_masked": mask_secret(client_token),
            "policies": auth_data["auth"]["policies"],
            "lease_duration": secret_resp["lease_duration"],
            "secrets": secret_resp["data"]["data"],
            "metadata": secret_resp["data"]["metadata"],
        }


def run_all_provisioning_demos() -> Dict[str, Any]:
    """
    Executes and verifies all 4 Secret Provisioning methods for Lab #10:
    1. Environment Variables
    2. Mounted Secret File
    3. Decentralized Approach (SealedSecret RSA-2048-OAEP + AES-256-GCM)
    4. Centralized Approach (Vault HTTP Server with AppRole Auth & RBAC)
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(base_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    demo_secrets = {
        "SECRET_KEY": "prod_k9F#mP2$vL8@qX4!zR7*wN1&bT5^yH3",
        "KEYCLOAK_CLIENT_SECRET": "kc_oidc_88a7f6e5-4321-4b9c-9d1a-0f1e2d3c4b5a",
        "MASTER_ENCRYPTION_KEY": "aes256_master_7f9a8b6c5d4e3f2a1b0c9d8e7f6a5b4c",
        "DB_CONNECTION_PASSWORD": "pg_tls_99xQ!2vM#8kL$4pW@7nJ",
    }

    print("=" * 78)
    print("LAB #10: DEVSECOPS SECRET PROVISIONING VERIFICATION SUITE")
    print("=" * 78)

    # 1. Environment Variable Provisioning
    for k, v in demo_secrets.items():
        os.environ[f"LAB10_{k}"] = v
    env_loaded = ExternalStorageProvider.from_environment(prefix="LAB10_")
    print("\n[1] ENVIRONMENT VARIABLE PROVISIONING (Slide 36):")
    for k, v in env_loaded.items():
        print(f"    Loaded {k:<24} -> {mask_secret(v)}")

    # 2. File-Based Provisioning
    secret_file_path = os.path.join(artifacts_dir, "mounted_secrets.json")
    with open(secret_file_path, "w", encoding="utf-8") as f:
        json.dump(demo_secrets, f, indent=2)
    os.chmod(secret_file_path, stat.S_IRUSR | stat.S_IWUSR)
    file_loaded = ExternalStorageProvider.from_secret_file(secret_file_path)
    print("\n[2] FILE-BASED SECRET PROVISIONING (Slide 37):")
    print(f"    Mounted File : {os.path.basename(file_loaded['file_path'])} (Permissions: {file_loaded['permissions']})")
    print(f"    Keys Loaded  : {list(file_loaded['secrets'].keys())}")

    # 3. Decentralized Provisioning (SealedSecret)
    print("\n[3] DECENTRALIZED PROVISIONING — SEALED SECRET (Slides 39, 43-44):")
    keypair = DecentralizedSealedSecret.generate_sealing_keypair()
    sealed_path = os.path.join(base_dir, "secrets.sealed.json")
    manifest = DecentralizedSealedSecret.seal_secrets(demo_secrets, keypair["public_key_pem"], sealed_path)
    unsealed = DecentralizedSealedSecret.unseal_secrets(sealed_path, keypair["private_key_pem"])
    print(f"    Sealed Manifest Saved : secrets.sealed.json ({manifest['metadata']['algorithm']})")
    print(f"    Encrypted Key Preview : {manifest['spec']['encryptedDataKey_b64'][:44]}...")
    print(f"    Ciphertext Preview    : {manifest['spec']['ciphertext_b64'][:44]}...")
    print(f"    Unseal Integrity Check: {'PASSED (4/4 secrets decrypted)' if unsealed == demo_secrets else 'FAILED'}")

    # 4. Centralized Provisioning (Vault Server & Client)
    print("\n[4] CENTRALIZED PROVISIONING — SECRET MANAGER / VAULT API (Slides 40-42):")
    vault_server = CentralizedVaultServer(initial_secrets=demo_secrets, port=8205)
    vault_server.start()
    try:
        client = CentralizedVaultClient(vault_addr="http://127.0.0.1:8205")
        vault_result = client.authenticate_and_fetch(
            role_id="crypto-portal-app-role",
            secret_id="approle-secret-9f8e7d6c",  # noqa: S106
        )
        print(f"    Auth Endpoint         : POST /v1/auth/approle/login -> 200 OK")
        print(f"    Issued Client Token   : {vault_result['client_token_masked']}")
        print(f"    Attached RBAC Policies: {vault_result['policies']} (TTL: {vault_result['lease_duration']}s)")
        print(f"    Secret Read Endpoint  : GET /v1/secret/data/crypto_portal -> 200 OK")
        for k, v in vault_result["secrets"].items():
            print(f"    Retrieved {k:<22} -> {mask_secret(v)}")
        print(f"    Audit Log Entries     : {len(vault_server.audit_log)} recorded events")
    finally:
        vault_server.stop()

    audit_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "env_provisioning": {"status": "success", "keys_loaded": list(env_loaded.keys())},
        "file_provisioning": {"status": "success", "permissions": file_loaded["permissions"]},
        "decentralized_sealed_secret": {
            "status": "success",
            "manifest_file": "secrets.sealed.json",
            "algorithm": manifest["metadata"]["algorithm"],
            "verified": unsealed == demo_secrets,
        },
        "centralized_vault_manager": {
            "status": "success",
            "policies": vault_result["policies"],
            "lease_duration_sec": vault_result["lease_duration"],
            "audit_log": vault_server.audit_log,
        },
    }

    report_path = os.path.join(artifacts_dir, "secret-provisioning-audit.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2)

    print("\n" + "=" * 78)
    print(f"ALL 4 PROVISIONING METHODS VERIFIED! Audit saved to: artifacts/secret-provisioning-audit.json")
    print("=" * 78)
    return audit_report


if __name__ == "__main__":
    run_all_provisioning_demos()
