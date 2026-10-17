import os
import hashlib
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

# ==============================================================================
# Module 1: Symmetric Cryptography (AES-256-GCM + PBKDF2-HMAC-SHA256)
# ==============================================================================

def derive_key_pbkdf2(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """
    Derives a 256-bit (32 bytes) encryption key from a master password and random salt
    using PBKDF2 with HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_aes_gcm(plaintext: str, password: str, associated_data: str = "") -> Dict[str, Any]:
    """
    Encrypts plaintext using AES-256-GCM with a key derived from password + random 16-byte salt.
    Nonce is 12 bytes (standard recommended length for GCM).
    Returns ciphertext and authentication tag separately for educational inspection.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    salt = os.urandom(16)
    key = derive_key_pbkdf2(password, salt)
    
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aad_bytes = associated_data.encode("utf-8") if associated_data else None
    
    aesgcm = AESGCM(key)
    # cryptography AESGCM.encrypt appends 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)
    
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    
    full_payload = salt + nonce + ct_with_tag
    
    return {
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "key_derived_hex": key.hex(),
        "full_payload_b64": base64.b64encode(full_payload).decode("ascii"),
        "associated_data": associated_data
    }

def decrypt_aes_gcm(
    ciphertext_hex: str,
    tag_hex: str,
    nonce_hex: str,
    salt_hex: str,
    password: str,
    associated_data: str = ""
) -> str:
    """
    Decrypts AES-256-GCM ciphertext. Verifies integrity tag.
    Raises InvalidTag if tag mismatch occurs (data was tampered or wrong password).
    """
    try:
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal encoding in input parameters: {e}")

    key = derive_key_pbkdf2(password, salt)
    aesgcm = AESGCM(key)
    aad_bytes = associated_data.encode("utf-8") if associated_data else None
    
    # Reassemble ciphertext + tag expected by cryptography library
    ct_with_tag = ciphertext + tag
    
    decrypted_bytes = aesgcm.decrypt(nonce, ct_with_tag, aad_bytes)
    return decrypted_bytes.decode("utf-8")

def tamper_ciphertext(ciphertext_hex: str) -> str:
    """
    Simulates a bit-flipping / active tampering attack by altering one byte of the ciphertext.
    """
    raw_ct = bytearray(bytes.fromhex(ciphertext_hex))
    if len(raw_ct) == 0:
        return "00"
    # Flip the lowest bit of the first byte
    raw_ct[0] ^= 0x01
    return bytes(raw_ct).hex()


# ==============================================================================
# Module 2: Asymmetric Cryptography & Digital Signature (Ed25519 + SHA-256)
# ==============================================================================

def generate_ed25519_keypair() -> Dict[str, str]:
    """
    Generates an Ed25519 asymmetric keypair and exports them in PEM format.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return {
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem
    }

def sign_document(document_bytes: bytes, private_key_pem: str) -> Dict[str, Any]:
    """
    Calculates SHA-256 hash of the document and generates an Ed25519 digital signature.
    """
    try:
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
    except Exception as e:
        raise ValueError(f"Invalid Private Key PEM: {e}")
    
    if not isinstance(priv_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key must be an Ed25519 private key")

    # Calculate SHA-256 digest for audit and verification visibility
    sha256_hash = hashlib.sha256(document_bytes).hexdigest()
    
    # Ed25519 natively signs the message (internally applying SHA-512)
    signature = priv_key.sign(document_bytes)
    
    return {
        "sha256_hex": sha256_hash,
        "signature_hex": signature.hex(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "document_size_bytes": len(document_bytes)
    }

def verify_document_signature(document_bytes: bytes, signature_hex: str, public_key_pem: str) -> Dict[str, Any]:
    """
    Verifies an Ed25519 digital signature against a document and public key.
    Returns status and SHA-256 calculation.
    """
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid Public Key PEM: {e}")
        
    if not isinstance(pub_key, ed25519.Ed25519PublicKey):
        raise ValueError("Key must be an Ed25519 public key")

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        raise ValueError("Signature must be a valid hexadecimal string")

    sha256_hash = hashlib.sha256(document_bytes).hexdigest()
    
    try:
        pub_key.verify(signature, document_bytes)
        is_valid = True
        error_msg = None
    except InvalidSignature:
        is_valid = False
        error_msg = "Signature does not match the document content or public key!"
    except Exception as e:
        is_valid = False
        error_msg = str(e)
        
    return {
        "is_valid": is_valid,
        "sha256_hex": sha256_hash,
        "error_message": error_msg
    }

def tamper_document_text(document_text: str) -> str:
    """
    Simulates a fraudulent modification of the document (subtly alters 1 character).
    """
    if not document_text:
        return "Altered content"
    if document_text.endswith("."):
        return document_text[:-1] + "!"
    return document_text + " [MODIFIED]"
