use rand::rngs::OsRng;
use rand::Rng;

pub const CHAR_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const CHAR_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const CHAR_NUMBER: &[u8] = b"0123456789";
pub const CHAR_SYMBOL: &[u8] = b"!@#$%&*()_+-=[]?";

/**
 * Genera una contraseña criptográficamente segura de longitud especificada.
 *
 * Utiliza muestreo de rechazo (rejection sampling) uniforme a nivel de contraseña completa
 * sobre un conjunto de 78 caracteres legibles (26 minúsculas, 26 mayúsculas, 10 números, 16 símbolos).
 * Esto elimina el sesgo de módulo (modulo bias) y garantiza que cada contraseña cumpla
 * la política de tener al menos:
 * - 1 letra minúscula
 * - 1 letra mayúscula
 * - 1 dígito numérico
 * - 1 símbolo especial
 */
pub fn generate_secure_password(length: usize) -> Result<String, String> {
    if length < 4 {
        return Err("La longitud de la contraseña debe ser al menos 4 caracteres.".to_string());
    }

    // Unir todos los conjuntos permitidos (total 78 caracteres)
    let mut allowed_base = Vec::with_capacity(78);
    allowed_base.extend_from_slice(CHAR_LOWER);
    allowed_base.extend_from_slice(CHAR_UPPER);
    allowed_base.extend_from_slice(CHAR_NUMBER);
    allowed_base.extend_from_slice(CHAR_SYMBOL);

    let mut rng = OsRng;

    // Rejection sampling puro
    loop {
        let mut password_chars = Vec::with_capacity(length);
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_number = false;
        let mut has_symbol = false;

        for _ in 0..length {
            let idx = rng.gen_range(0..allowed_base.len());
            let b = allowed_base[idx];
            if CHAR_LOWER.contains(&b) {
                has_lower = true;
            } else if CHAR_UPPER.contains(&b) {
                has_upper = true;
            } else if CHAR_NUMBER.contains(&b) {
                has_number = true;
            } else if CHAR_SYMBOL.contains(&b) {
                has_symbol = true;
            }
            password_chars.push(b);
        }

        if has_lower && has_upper && has_number && has_symbol {
            return String::from_utf8(password_chars)
                .map_err(|e| format!("Error generando cadena de contraseña: {}", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_password_length_validation() {
        assert!(generate_secure_password(0).is_err());
        assert!(generate_secure_password(1).is_err());
        assert!(generate_secure_password(2).is_err());
        assert!(generate_secure_password(3).is_err());
        assert!(generate_secure_password(4).is_ok());
    }

    #[test]
    fn test_generate_secure_password_guarantees_all_classes() {
        for &len in &[4, 8, 16, 32] {
            for _ in 0..200 {
                let pwd = generate_secure_password(len).expect("generación exitosa");
                assert_eq!(pwd.len(), len, "la longitud debe coincidir exactamente");

                let bytes = pwd.as_bytes();
                assert!(bytes.iter().any(|b| CHAR_LOWER.contains(b)), "debe contener al menos una minúscula");
                assert!(bytes.iter().any(|b| CHAR_UPPER.contains(b)), "debe contener al menos una mayúscula");
                assert!(bytes.iter().any(|b| CHAR_NUMBER.contains(b)), "debe contener al menos un número");
                assert!(bytes.iter().any(|b| CHAR_SYMBOL.contains(b)), "debe contener al menos un símbolo");
            }
        }
    }
}
