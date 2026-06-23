# PDF Digital Signature Service (PKCS#11)

A production‑ready Spring Boot REST API that digitally signs PDF documents using a **PKCS#11 hardware security token** (HSM, smart card, or SoftHSM2 simulator).  
The private key **never leaves the cryptographic device** — all signing operations happen inside the token.

---

## Architecture

```
┌──────────┐   POST /sign    ┌─────────────────┐   PKCS#11 C_Sign   ┌──────────────┐
│  Client  │ ──────────────► │  Spring Boot     │ ────────────────► │  HSM / Token  │
│          │ ◄────────────── │  REST API        │ ◄──────────────── │  (SoftHSM2)   │
└──────────┘   signed PDF    └─────────────────┘   signature        └──────────────┘
```

### How It Works

1. **Upload** – Client sends a PDF via `POST /sign` (multipart form-data).
2. **Hash** – The service computes a SHA‑256 hash of the PDF content.
3. **Sign** – The hash is sent to the PKCS#11 token; the token returns an RSA signature.
4. **CMS Encode** – Bouncy Castle wraps the signature in a PKCS#7 (CMS) detached signature.
5. **Embed** – PDFBox embeds the CMS signature into the PDF (incremental save).
6. **Return** – The signed PDF is returned as a downloadable file.

---

## Tech Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| Java | 17 | Runtime |
| Spring Boot | 3.4.1 | REST framework |
| Apache PDFBox | 3.0.1 | PDF manipulation & signature embedding |
| Bouncy Castle | 1.78 | CMS/PKCS#7 signature structure |
| Lombok | 1.18.30 | Boilerplate reduction |
| SoftHSM2 | 2.6 | PKCS#11 token (development/testing) |

---

## Project Structure

```
src/main/java/com/example/pdf_signer/
├── PdfSignerApplication.java        # Spring Boot entry point
├── PdfSignerController.java         # REST endpoints
├── PdfSigningService.java           # Signing logic & HSM integration
├── Pkcs11Config.java                # PKCS#11 provider configuration
src/main/resources/
├── application.properties           # App config
├── pkcs11.cfg                       # PKCS#11 library config
```

---

## Quick Start (with SoftHSM2)

### 1. Install SoftHSM2
```bash
sudo apt install softhsm2 opensc
```

### 2. Initialize a token
```bash
softhsm2-util --init-token --free --label "MyToken" --pin 123456 --so-pin 12345678
```
Note the slot number from the output.

### 3. Generate a signing key & certificate
```bash
keytool -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 \
  -providerArg src/main/resources/pkcs11.cfg \
  -genkeypair -alias signingkey -keyalg RSA -keysize 2048 \
  -dname "CN=Test Signer, O=MyOrg, C=US" \
  -storepass 123456 -keypass 123456
```

### 4. Configure the application

**`src/main/resources/pkcs11.cfg`**
```properties
name = SoftHSM
library = /usr/lib/softhsm/libsofthsm2.so
slot = YOUR_SLOT_NUMBER
```

**`src/main/resources/application.properties`**
```properties
pkcs11.pin=123456
```

### 5. Run
```bash
./mvnw spring-boot:run
```

### 6. Sign a PDF
- Open `http://localhost:8080/` in your browser
- Upload a PDF and click **Sign PDF**

Or via cURL:
```bash
curl -F "file=@document.pdf" http://localhost:8080/sign --output signed.pdf
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | HTML upload form |
| `POST` | `/sign` | Upload PDF (`file` param) → returns signed PDF |
| `GET` | `/health` | Health check |

---

## Configuration Reference

| Property | Description | Default |
|----------|-------------|---------|
| `pkcs11.config-path` | Path to PKCS#11 config | `classpath:pkcs11.cfg` |
| `pkcs11.pin` | Token user PIN | – |

---

## Production Considerations

- ✅ Use a real HSM (Thales, Utimaco, YubiKey) instead of SoftHSM2
- ✅ Store the PIN in a secrets manager (HashiCorp Vault, AWS Secrets Manager)
- ✅ Add PKCS#11 session pooling for concurrent requests
- ✅ Enable TLS on the REST endpoint
- ✅ Add authentication/authorization to the API
- ✅ Validate certificate trust chains before signing

---

