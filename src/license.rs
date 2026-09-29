use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LICENSE_BINARY_LENGTH: usize = 78;
pub const LICENSE_PAYLOAD_LENGTH: usize = 14;

/**
 * Payload contenido en la licencia firmada (formato binario compacto de 14 bytes).
 */
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LicensePayload {
    pub email_hash: String,
    pub plan: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

// -----------------------------------------------------------------------------
// Base32 RFC 4648 (sin relleno)
// -----------------------------------------------------------------------------
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decodifica una cadena Base32 RFC 4648 ignorando guiones, espacios y saltos de línea.
 */
pub fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'-' && b != b' ' && b != b'\n' && b != b'\r' && b != b'\t')
        .map(|b| b.to_ascii_uppercase())
        .collect();

    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    let mut output = Vec::new();

    for byte in clean {
        let val = match BASE32_ALPHABET.iter().position(|&c| c == byte) {
            Some(idx) => idx as u32,
            None => return Err(format!("Carácter inválido en clave de licencia: '{}'", byte as char)),
        };

        value = (value << 5) | val;
        bits += 5;

        if bits >= 8 {
            output.push(((value >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
    }

    Ok(output)
}

/**
 * Codifica bytes a Base32 RFC 4648 sin relleno (útil para generar claves de licencia de prueba).
 */
pub fn encode_base32(data: &[u8]) -> String {
    let mut result = String::new();
    let mut bits = 0u32;
    let mut value = 0u32;

    for &byte in data {
        value = (value << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = (value >> (bits - 5)) & 0x1F;
            result.push(BASE32_ALPHABET[index as usize] as char);
            bits -= 5;
        }
    }

    if bits > 0 {
        let index = (value << (5 - bits)) & 0x1F;
        result.push(BASE32_ALPHABET[index as usize] as char);
    }

    result
}

/**
 * Mecanismo criptográfico genérico para verificar firmas Ed25519 de licencias offline
 * en un timestamp específico.
 *
 * Estructura de la clave (78 bytes decodificados):
 * - Bytes 0..14: Payload binario (versión, plan, issued_at, expires_at, email_hash)
 * - Bytes 14..78: Firma Ed25519 de 64 bytes calculada sobre el payload
 */
pub fn verify_license_at(
    key: &str,
    public_key: &[u8; 32],
    revoked_hashes: &[&str],
    current_time: u64,
) -> Result<LicensePayload, String> {
    let raw_bytes = decode_base32(key)?;

    if raw_bytes.len() != LICENSE_BINARY_LENGTH {
        return Err(format!(
            "La clave de licencia no tiene la longitud requerida (longitud: {}, esperada: {}).",
            raw_bytes.len(),
            LICENSE_BINARY_LENGTH
        ));
    }

    let payload_bytes = &raw_bytes[..LICENSE_PAYLOAD_LENGTH];
    let signature_bytes: [u8; 64] = raw_bytes[LICENSE_PAYLOAD_LENGTH..]
        .try_into()
        .map_err(|_| "Formato de firma inválido.".to_string())?;

    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| format!("Error en clave pública de verificación: {}", e))?;

    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(payload_bytes, &signature)
        .map_err(|_| "Firma de licencia inválida. La clave ha sido alterada o no corresponde a esta aplicación.".to_string())?;

    // Validar lista de revocación criptográfica (hash SHA-256 de los bytes de la firma)
    let sig_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&signature_bytes);
        format!("{:x}", hasher.finalize())
    };

    if revoked_hashes.contains(&sig_hash.as_str()) {
        return Err("Esta clave de licencia ha sido revocada por el emisor.".to_string());
    }

    let version = payload_bytes[0];
    if version != 1 {
        return Err(format!("Versión de formato de licencia no soportada: {}", version));
    }

    let plan_code = payload_bytes[1];
    let plan = match plan_code {
        1 => "pro".to_string(),
        2 => "trial".to_string(),
        _ => "pro".to_string(),
    };

    let issued_at = u32::from_be_bytes(payload_bytes[2..6].try_into().unwrap()) as u64;
    let expires_at_raw = u32::from_be_bytes(payload_bytes[6..10].try_into().unwrap()) as u64;

    let expires_at = if expires_at_raw > 0 {
        if expires_at_raw < current_time {
            return Err("La clave de licencia ha expirado.".to_string());
        }
        Some(expires_at_raw)
    } else {
        None
    };

    let email_hash = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        payload_bytes[10], payload_bytes[11], payload_bytes[12], payload_bytes[13]
    );

    Ok(LicensePayload {
        email_hash,
        plan,
        issued_at,
        expires_at,
    })
}

/**
 * Mecanismo criptográfico genérico para verificar firmas Ed25519 de licencias offline
 * usando la hora del sistema.
 */
pub fn verify_license(
    key: &str,
    public_key: &[u8; 32],
    revoked_hashes: &[&str],
) -> Result<LicensePayload, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    verify_license_at(key, public_key, revoked_hashes, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_test_signing_key() -> SigningKey {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    }

    #[test]
    fn test_base32_decode_valid() {
        let decoded = decode_base32("JBSWY3DPEBLW64TMMQ").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_license_creation_and_verification_generic() {
        let signing_key = generate_test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // Construir payload: v=1, plan=1 (pro), issued=1000, expires=0 (vitalicio), email_hash=[0x12, 0x34, 0x56, 0x78]
        let mut payload = Vec::with_capacity(LICENSE_PAYLOAD_LENGTH);
        payload.push(1u8); // version
        payload.push(1u8); // plan: pro
        payload.extend_from_slice(&1000u32.to_be_bytes()); // issued_at
        payload.extend_from_slice(&0u32.to_be_bytes()); // expires_at = 0
        payload.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // email_hash

        let signature = signing_key.sign(&payload);

        let mut binary_key = Vec::with_capacity(LICENSE_BINARY_LENGTH);
        binary_key.extend_from_slice(&payload);
        binary_key.extend_from_slice(&signature.to_bytes());

        let base32_key = encode_base32(&binary_key);

        // Verificar con función genérica
        let verified = verify_license(&base32_key, &pub_bytes, &[]).expect("Verification failed");
        assert_eq!(verified.plan, "pro");
        assert_eq!(verified.issued_at, 1000);
        assert_eq!(verified.expires_at, None);
        assert_eq!(verified.email_hash, "12345678");
    }

    #[test]
    fn test_expired_license_fails() {
        let signing_key = generate_test_signing_key();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        // Expira en timestamp 500
        let mut payload = Vec::with_capacity(LICENSE_PAYLOAD_LENGTH);
        payload.push(1u8);
        payload.push(1u8);
        payload.extend_from_slice(&100u32.to_be_bytes());
        payload.extend_from_slice(&500u32.to_be_bytes());
        payload.extend_from_slice(&[0xab, 0xcd, 0xef, 0x01]);

        let signature = signing_key.sign(&payload);
        let mut binary_key = Vec::new();
        binary_key.extend_from_slice(&payload);
        binary_key.extend_from_slice(&signature.to_bytes());
        let key_str = encode_base32(&binary_key);

        // Evaluar en tiempo 600 (> 500)
        let res = verify_license_at(&key_str, &pub_bytes, &[], 600);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("ha expirado"));
    }

    #[test]
    fn test_revoked_license_fails() {
        let signing_key = generate_test_signing_key();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let mut payload = Vec::with_capacity(LICENSE_PAYLOAD_LENGTH);
        payload.push(1u8);
        payload.push(1u8);
        payload.extend_from_slice(&100u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let signature = signing_key.sign(&payload);
        let mut binary_key = Vec::new();
        binary_key.extend_from_slice(&payload);
        binary_key.extend_from_slice(&signature.to_bytes());

        let sig_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&signature.to_bytes());
            format!("{:x}", hasher.finalize())
        };

        let key_str = encode_base32(&binary_key);

        let res = verify_license(&key_str, &pub_bytes, &[&sig_hash]);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("ha sido revocada"));
    }
}
