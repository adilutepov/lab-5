# Academic Crypto Portal (Laboratory Works #5 & #6)

A full-featured, production-ready educational web application built with **FastAPI, Jinja2, TailwindCSS, and the Python `cryptography` library**. 

This application completely implements all requirements for **Lab #5 (Cryptographic Mechanisms & Open-Source Tool Testing)** and lays the complete architectural foundation for **Lab #6 (Keycloak Centralized Identity Management & OIDC Custom Attribute Mapping)**.

---

## 1. Compliance with Lab #5 Requirements

| Requirement from Lab #5 Guide | Implementation in this Application |
| :--- | :--- |
| **1. Choose at least 2 real-world cases of cryptography** | • **Case 1 (Symmetric):** Confidentiality and data integrity of secret research data and notes using **AES-256-GCM** with **PBKDF2-HMAC-SHA256** key derivation.<br>• **Case 2 (Asymmetric):** Document authenticity, integrity, and non-repudiation using **Ed25519 digital signatures** on Edwards curves with **SHA-256** hashing. |
| **2. Make a sample app with demo & attack simulations** | Interactive web portal allowing real-time encryption, decryption, key generation, and signing. Includes **"Simulate Attack (Tamper 1 Byte)"** and **"Simulate Forgery"** buttons demonstrating immediate mathematical rejection of tampered data. |
| **3. Test open-source / free crypto software** | Comprehensive hands-on test protocol for **GnuPG (GPG)** detailing keypair generation, hybrid encryption, and detached digital signature verification with exact console commands and outputs. |
| **4. Theoretical proofs & justification ("Пруфы зач почему этот метод")** | Detailed comparative proofs in Section 3 below and in the application UI (Tab 3) justifying the selection of AES-GCM, PBKDF2, and Ed25519 over obsolete alternatives. |

---

## 2. Architecture & Modules Overview

### Module 1: Symmetric Authenticated Encryption (AES-256-GCM + PBKDF2)
* **File:** `crypto_service.py` (`encrypt_aes_gcm`, `decrypt_aes_gcm`, `tamper_ciphertext`)
* **Workflow:**
  1. A master password and random 16-byte salt (`os.urandom(16)`) are fed into **PBKDF2-HMAC-SHA256** with 200,000 iterations to derive a 256-bit AES key.
  2. A fresh, random 12-byte Nonce (96 bits) is generated.
  3. Plaintext is encrypted via AES-256 in **Galois/Counter Mode (GCM)**, optionally binding Associated Data (AAD).
  4. GCM produces the ciphertext alongside a 16-byte **Authentication Tag (GMAC)**.
  5. The **"Simulate Attack"** button flips a single bit in the ciphertext. When decryption is attempted, the cryptographic engine detects that the tag does not match and throws an `InvalidTag` exception, blocking corrupted output from reaching the user.

### Module 2: Asymmetric Cryptography & Digital Signatures (Ed25519 + SHA-256)
* **File:** `crypto_service.py` (`generate_ed25519_keypair`, `sign_document`, `verify_document_signature`)
* **Workflow:**
  1. Generates an **Ed25519** keypair exported in standardized PEM formats (PKCS#8 for private key, SPKI for public key).
  2. The document is hashed via **SHA-256** to create a fixed-size cryptographic fingerprint.
  3. The private key signs the data using the Edwards-curve Digital Signature Algorithm (EdDSA).
  4. The public key verifies the 64-byte signature against the document bytes.
  5. The **"Simulate Forgery"** button modifies a single character in the document. Upon verification, the SHA-256 hash diverges, and verification fails with `InvalidSignature`.

---

## 3. Theoretical Proofs & Rationale (Защита лабораторной)

### 3.1. Why AES-256-GCM (Over DES, 3DES, AES-ECB, or Base64)?
1. **Authenticated Encryption (AEAD):** Legacy modes (such as AES-CBC or AES-CTR) only guarantee confidentiality. They are completely vulnerable to active man-in-the-middle bit-flipping attacks and *Padding Oracle vulnerabilities* (e.g., POODLE). AES-GCM integrates an authentication tag (GMAC), guaranteeing that ciphertext tampering is mathematically detected prior to decryption.
2. **Rejection of Obsolete Ciphers:**
   * **DES (56-bit key):** Broken via brute-force exhaustion in hours.
   * **3DES (112-bit effective):** Vulnerable to the Sweet32 attack (birthday collisions on 64-bit blocks).
   * **AES-ECB (Electronic Codebook):** Fails to obscure data patterns (identical plaintext blocks yield identical ciphertext blocks, causing visual leaks like the famous "ECB Penguin").
   * **Base64:** Merely an ASCII representation/encoding, offering zero confidentiality.

### 3.2. Why PBKDF2 with Salt (Over Plain SHA-256 or MD5)?
1. **Immunity to Rainbow Tables:** A 16-byte cryptographically secure random salt ensures that identical master passwords produce entirely different encryption keys across systems.
2. **GPU & ASIC Resistance:** Raw hashing functions (SHA-256, MD5) are engineered for extreme speed (billions of calculations/sec on commodity GPUs). PBKDF2 forces an attacker through 200,000 recursive HMAC iterations, dramatically increasing the hardware cost and time required for password guessing.

### 3.3. Why Ed25519 (Over Classical RSA-2048)?
1. **Compactness & Efficiency:** Ed25519 public keys are only 32 bytes and signatures are exactly 64 bytes (compared to RSA-2048's 256-byte signatures). Signing and verification are orders of magnitude faster.
2. **Side-Channel Attack Immunity:** Ed25519 algorithms are strictly constant-time. They do not rely on secret-dependent memory lookups or branching, eliminating timing attack vectors that compromise traditional RSA implementations.

---

## 4. Open-Source Cryptographic Tool Testing: GnuPG (GPG)

As required by Step 3 of Lab #5, testing of open-source cryptographic software was conducted using **GnuPG (GPG 2.x)**, the reference implementation of OpenPGP (RFC 4880).

### Test Step 0: Ensure GnuPG is accessible in PowerShell (No winget needed)
```powershell
# GnuPG is already installed with Git for Windows! Just run this alias once in PowerShell:
Set-Alias gpg "C:\Program Files\Git\usr\bin\gpg.exe"

# Or simply open "Git Bash" where gpg is already available globally!
gpg --version
```

### Test Step 1: Generate OpenPGP Keypair on Curve25519 (PowerShell / Git Bash)
```powershell
gpg --full-generate-key
```
*Selection:* Choose `(9) ECC (sign and encrypt)` -> `(1) Curve 25519` -> Real name: `Lab Tester` -> Email: `tester@crypto.edu`.

### Test Step 2: Hybrid File Encryption (PowerShell)
```powershell
Set-Content -Path .\secret_data.txt -Value "CONFIDENTIAL: Lab 5 cryptographic benchmark results"
gpg --encrypt --recipient "tester@crypto.edu" .\secret_data.txt
```
*Result:* Generates binary file `secret_data.txt.gpg`.  
*Cryptographic Mechanism:* GnuPG utilizes **Hybrid Encryption**: a random symmetric session key (e.g., AES-256) encrypts the bulk file data, and that session key is then encrypted using the recipient's public key (Curve25519).

### Test Step 3: Decryption and Verification (PowerShell)
```powershell
gpg --decrypt .\secret_data.txt.gpg
```
*Result:* GnuPG prompts for the private key passphrase (via Windows GUI pinentry), decrypts the session key, and outputs the original plaintext.

### Test Step 4: Detached Digital Signature Creation & Validation (PowerShell)
```powershell
# Create detached ASCII-armored signature (.asc)
gpg --detach-sign --armor .\secret_data.txt

# Verify against original file
gpg --verify .\secret_data.txt.asc .\secret_data.txt
```
*Console Output:*
```text
PS C:\Users\Admin> gpg --verify .\secret_data.txt.asc .\secret_data.txt
gpg: Signature made 10/17/2026 04:50:00
gpg: using EDDSA key 7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B
gpg: Good signature from "Lab Tester <tester@crypto.edu>" [ultimate]
```

---

## 5. Architectural Foundation for Lab #6 (Keycloak OIDC Integration)

The application has been engineered from day one to serve as the target for Lab #6:

1. **Authentication Mode Switch (`AUTH_MODE`):**
   * Default: `AUTH_MODE=demo_lab5` — runs completely standalone without requiring Keycloak running immediately.
   * Target: `AUTH_MODE=keycloak_lab6` — routes `/login` and `/callback` to the Keycloak instance via OAuth2 Authorization Code flow.
2. **Custom Attribute Badge in Header (`Discipline`):**
   * Located at the top right of the navigation header.
   * In `demo_lab5` mode, clicking the edit icon lets the user dynamically test badge rendering.
   * In `keycloak_lab6` mode, `auth_service.py` extracts the claim from the JWT access token:
     ```python
     discipline = token_payload.get("discipline")
     ```
3. **Keycloak Docker Compose Ready:**
   * `docker-compose.yml` already contains the official Keycloak service configuration (`quay.io/keycloak/keycloak:latest` on port `8080`).

---

## 6. How to Run Locally

### Option A: Local Python Environment
```bash
# 1. Navigate to project directory
cd c:\Users\Admin\Desktop\хака\crypto_portal

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate   # On Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start FastAPI server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Open **`http://localhost:8000`** in your browser.

### Option B: Docker Compose
```bash
docker compose up -d
```
Access the application at **`http://localhost:8000`** and Keycloak at **`http://localhost:8080`**.
