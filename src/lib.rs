//! # MPLock Core (`mplock-core`)
//!
//! Biblioteca criptográfica y de almacenamiento independiente para el gestor de contraseñas MPLock.
//! Provee cifrado autenticado de bóvedas (AES-256-GCM + PBKDF2), generación de contraseñas seguras,
//! autenticación de dos factores (TOTP RFC 6238) y verificación criptográfica offline de licencias Ed25519.
//!
//! Este crate es 100% independiente de Tauri, del frontend web y de pasarelas comerciales.

pub mod crypto;
pub mod license;
pub mod password;
pub mod storage;
pub mod totp;

// Re-exportaciones de conveniencia
pub use crypto::{decrypt, derive_key, encrypt, KEY_LEN, PBKDF2_ITERATIONS, SALT_LEN, IV_LEN};
pub use license::{
    decode_base32, encode_base32, verify_license, verify_license_at, LicensePayload,
    LICENSE_BINARY_LENGTH, LICENSE_PAYLOAD_LENGTH,
};
pub use password::generate_secure_password;
pub use storage::{
    default_credential_id, generate_recovery_code, initialize_db, load_db, save_db, Credential,
    UnlockMethod, UnlockedVault, Vault,
};
pub use totp::{generate_totp_code, generate_totp_code_at, parse_otpauth_uri, TotpResponse};
