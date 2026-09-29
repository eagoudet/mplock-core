use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::hmac::SimpleHmac;
use pbkdf2::pbkdf2;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const SALT_LEN: usize = 16;
pub const IV_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/**
 * Deriva una clave AES-256 a partir de una contraseña y un salt usando PBKDF2-HMAC-SHA256.
 */
pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32, key: &mut [u8]) {
    pbkdf2::<SimpleHmac<Sha256>>(password, salt, iterations, key)
        .expect("PBKDF2 key derivation failed");
}

/**
 * Cifra texto plano usando una contraseña con AES-256-GCM y PBKDF2 (600,000 iteraciones).
 * Retorna un String en Base64 con el payload empaquetado:
 * [Salt (16 bytes)] + [IV (12 bytes)] + [Ciphertext + Auth Tag (Variable)]
 */
pub fn encrypt(plain_text: &str, password: &[u8]) -> Result<String, String> {
    // 1. Generar Salt aleatorio (16 bytes)
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 2. Derivar Clave AES-256
    let mut key_bytes = [0u8; KEY_LEN];
    derive_key(password, &salt, PBKDF2_ITERATIONS, &mut key_bytes);

    // 3. Generar IV / Nonce aleatorio (12 bytes)
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);

    // 4. Inicializar cifrador AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Error al inicializar el cifrador: {}", e))?;

    // Limpiar los bytes de la clave de la memoria lo antes posible
    key_bytes.zeroize();

    // 5. Cifrar
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|e| format!("Fallo durante el cifrado: {}", e))?;

    // 6. Concatenar Salt + IV + Ciphertext
    let mut payload = Vec::with_capacity(salt.len() + iv.len() + ciphertext.len());
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&ciphertext);

    // 7. Codificar en Base64
    Ok(general_purpose::STANDARD.encode(payload))
}

/**
 * Descifra el payload en Base64 usando una contraseña.
 * Verifica la integridad del mensaje y autenticación del tag AES-GCM.
 */
pub fn decrypt(base64_payload: &str, password: &[u8]) -> Result<String, String> {
    // 1. Decodificar Base64
    let payload = general_purpose::STANDARD
        .decode(base64_payload)
        .map_err(|e| format!("Error al decodificar Base64: {}", e))?;

    if payload.len() < (SALT_LEN + IV_LEN) {
        return Err("El payload cifrado es demasiado corto o inválido".to_string());
    }

    // 2. Separar Salt, IV y Ciphertext
    let (salt, rest) = payload.split_at(SALT_LEN);
    let (iv, ciphertext) = rest.split_at(IV_LEN);

    // 3. Derivar la clave AES-256 usando el Salt extraído
    let mut key_bytes = [0u8; KEY_LEN];
    derive_key(password, salt, PBKDF2_ITERATIONS, &mut key_bytes);

    // 4. Inicializar cifrador
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Error al inicializar el cifrador: {}", e))?;

    // Limpiar clave de memoria
    key_bytes.zeroize();

    // 5. Descifrar y verificar integridad
    let nonce = Nonce::from_slice(iv);
    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Contraseña maestra incorrecta o datos corruptos: {}", e))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Texto descifrado no es UTF-8 válido: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret_text = "HelloWorldSecret123!@#áéíóú";
        let password = b"SuperSafePassword!999";

        let encrypted = encrypt(secret_text, password).expect("Encryption failed");
        assert_ne!(encrypted, secret_text);

        let decrypted = decrypt(&encrypted, password).expect("Decryption failed");
        assert_eq!(decrypted, secret_text);
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let secret_text = "Sensitive data";
        let password = b"CorrectPassword123";
        let wrong_password = b"WrongPassword456";

        let encrypted = encrypt(secret_text, password).unwrap();
        let result = decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Contraseña maestra incorrecta"));
    }

    #[test]
    fn test_decrypt_corrupted_payload_fails() {
        let secret_text = "Sensitive data";
        let password = b"CorrectPassword123";

        let encrypted = encrypt(secret_text, password).unwrap();
        // Alter base64 content
        let mut corrupted = encrypted.clone();
        corrupted.replace_range(10..15, "AAAAA");

        let result = decrypt(&corrupted, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_payload_fails() {
        let password = b"Pass123";
        // Less than 28 bytes Base64
        let short_b64 = general_purpose::STANDARD.encode(b"short");
        let result = decrypt(&short_b64, password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("demasiado corto"));
    }
}
