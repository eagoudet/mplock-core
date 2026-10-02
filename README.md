# mplock-core

Core cryptographic engine, vault storage architecture, and security utilities for the **MPLock** password manager, developed in Rust.

`mplock-core` is designed as a standalone crate, completely decoupled from UI frameworks (Tauri, Electron, Web), platform-specific implementations, and commercial infrastructure.

> 📖 **Cryptographic Specifications:** For an in-depth, honest, and verifiable analysis of the threat model, local-first encrypted storage, and memory hygiene, read our **[Architecture whitepaper](docs/WHITEPAPER.md)**.

---

## 🚀 Features

### 1. Vault Encryption & Decryption (`mplock_core::crypto`)
- **Encryption Algorithm:** AES-256-GCM (authenticated encryption with integrity verification via authentication tag).
- **Key Derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations**, adhering to current OWASP recommendations.
- **Encrypted Payload Format:** Binary packaging serialized in Base64:
  `[Salt (16 bytes)] + [Nonce/IV (12 bytes)] + [Ciphertext + Auth Tag (Variable)]`
- **Memory Hygiene:** Uses the `Zeroize` trait to wipe master passwords, ephemeral DEKs, and internal buffers from RAM upon drop.

### 2. Secure Vault & Storage Management (`mplock_core::storage`)
- **Envelope Key Architecture (DEK - Data Encryption Key):**
  - Generates a random 32-byte (256-bit) DEK.
  - The DEK is stored encrypted twice independently:
    1. Encrypted with the user's master password.
    2. Encrypted with a human-friendly recovery code.
- **Recovery Codes:** Generates 24-character random codes grouped in blocks (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`), excluding visually ambiguous characters (`0`, `O`, `1`, `I`).
- **Seamless Migration:** Transparent automatic upgrade from legacy single-key schemes to the envelope key model with persistent UUIDs.
- **Data Models:** `Credential` structure with persistent `id` and optional TOTP secret.

### 3. Cryptographically Secure Password Generator (`mplock_core::password`)
- Backed by the operating system CSPRNG (`rand::rngs::OsRng`).
- **Rejection Sampling:** Uniform and independent selection across 78 human-readable characters (ASCII lowercase, uppercase, digits, and symbols).
- **Zero Modulo Bias:** Enforces that every generated password contains at least one lowercase letter, one uppercase letter, one digit, and one special character.

### 4. 2FA / TOTP Authentication Engine (`mplock_core::totp`)
- **RFC 6238 Standard:** Generates 6-digit TOTP codes based on HMAC-SHA1 with 30-second time steps.
- **Expiration Calculation:** Precise calculation of remaining seconds in the current time window.
- **Base32 Secret Normalization:** Cleans spaces, dashes, and normalizes to uppercase with strict RFC 4648 alphabet validation.
- **URI Parser:** Automatically extracts secrets from standard `otpauth://totp/...` URIs.

### 5. Generic Ed25519 Cryptographic License Verification (`mplock_core::license`)
- **Offline License Verification:** Purely cryptographic verification of Ed25519 signatures over compact 14-byte binary payloads (version, plan, UNIX timestamps, and identity hash).
- **Cryptographic Revocation List:** Validates against SHA-256 hashes of revoked signatures.
- **Zero Commercial Coupling:** The library contains no hardcoded public keys or proprietary revocation lists; these are supplied by the API consumer.

---

## 🚫 What This Crate Does NOT Include (By Design)

To preserve the purity, security, and independence of the core, this crate **does NOT** include:
- ❌ **Tauri or GUI Dependencies:** Does not depend on Tauri, Wry, Webview, or any graphical interface libraries.
- ❌ **Commercial Payment Gateway Integrations:** Contains no SDKs or logic tied to Lemon Squeezy, Stripe, Gumroad, or external webhooks.
- ❌ **Private Keys:** No private or signing keys exist in the codebase.
- ❌ **Proprietary Commercial Public Keys:** The license verifier accepts the public key as a parameter (`&[u8; 32]`), allowing any key pair to be used.
- ❌ **Business Model Logic:** Specific commercial rules (such as free tier limits or trial duration) must reside in the consumer application.
- ❌ **Operating System Hardware Fingerprinting:** Performs no direct reading of Windows registry (`winreg`), WMI, or proprietary OS calls.

---

## 📦 Quick Start

Add `mplock-core` to your `Cargo.toml`:

```toml
[dependencies]
mplock-core = { version = "0.1.0" }
```

### Example: Encrypting and Decrypting Data
```rust
use mplock_core::crypto;

let password = b"MySuperSecureMasterPassword123!";
let data = "Confidential vault data";

// Encrypt with AES-256-GCM + PBKDF2 (600k iterations)
let payload_b64 = crypto::encrypt(data, password)?;

// Decrypt while verifying integrity and authenticity
let decrypted = crypto::decrypt(&payload_b64, password)?;
assert_eq!(decrypted, data);
```

### Example: Password Generation
```rust
use mplock_core::password;

// Generate a secure 20-character password guaranteeing all character classes
let secure_pass = password::generate_secure_password(20)?;
println!("Generated password: {}", secure_pass);
```

### Example: TOTP / 2FA Code Generation
```rust
use mplock_core::totp;

let secret = "JBSWY3DPEHPK3PXP";
let response = totp::generate_totp_code(secret)?;

println!("2FA Code: {}", response.code);
println!("Seconds remaining: {}", response.seconds_remaining);
```

### Example: Generic Ed25519 License Verification
```rust
use mplock_core::license;

let public_key: [u8; 32] = [/* 32 bytes of your Ed25519 public key */];
let revoked_hashes: &[&str] = &[]; // List of revoked SHA-256 hashes

let license_key = "AEAWR-PSFEA-...";
let payload = license::verify_license(license_key, &public_key, revoked_hashes)?;

println!("Plan: {}", payload.plan);
println!("Issued at timestamp: {}", payload.issued_at);
```

---

## 🧪 Running Tests

`mplock-core` includes a comprehensive unit test suite covering official test vectors (RFC 6238 for TOTP, encryption vectors, and password sampling):

```bash
cargo test -p mplock-core
```

---

## ⚖️ License

This project is dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

This dual-licensing scheme is the de facto standard in the Rust ecosystem (e.g., Serde, Tokio), providing maximum permissiveness for open-source projects (MIT) alongside explicit patent grants required by corporate environments (Apache-2.0).
