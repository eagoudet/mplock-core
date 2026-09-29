use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TotpResponse {
    pub code: String,
    pub seconds_remaining: u8,
}

/**
 * Normaliza y extrae el secreto Base32 de una cadena.
 * Soporta URIs otpauth://totp/... o cadenas Base32 directas con espacios o guiones.
 */
pub fn parse_otpauth_uri(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("El secreto TOTP no puede estar vacío".to_string());
    }

    let secret_raw = if trimmed.starts_with("otpauth://") {
        let parsed_url = Url::parse(trimmed)
            .map_err(|e| format!("URI otpauth inválida: {}", e))?;

        let mut found_secret = None;
        for (key, val) in parsed_url.query_pairs() {
            if key.eq_ignore_ascii_case("secret") {
                found_secret = Some(val.to_string());
                break;
            }
        }

        found_secret.ok_or_else(|| "La URI otpauth no contiene el parámetro 'secret'".to_string())?
    } else {
        trimmed.to_string()
    };

    // Normalizar: remover espacios, guiones y convertir a mayúsculas
    let normalized: String = secret_raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    if normalized.is_empty() {
        return Err("El secreto Base32 está vacío tras la normalización".to_string());
    }

    // Validar alfabeto Base32 (A-Z, 2-7, y opcionalmente relleno '=')
    for c in normalized.chars() {
        if !c.is_ascii_alphanumeric() && c != '=' {
            return Err(format!("Carácter inválido '{}' en el secreto Base32", c));
        }
        if c.is_ascii_alphabetic() && !matches!(c, 'A'..='Z') {
            return Err(format!("Carácter inválido '{}' en el secreto Base32", c));
        }
        if c.is_ascii_digit() && !matches!(c, '2'..='7') {
            return Err(format!(
                "Carácter inválido '{}' en el secreto Base32 (solo dígitos 2-7 permitidos)",
                c
            ));
        }
    }

    // Verificar que se puede decodificar usando totp_rs::Secret
    Secret::Encoded(normalized.clone())
        .to_bytes()
        .map_err(|e| format!("Secreto Base32 inválido: {:?}", e))?;

    Ok(normalized)
}

/**
 * Genera el código TOTP y segundos restantes en un instante dado (timestamp UNIX en segundos).
 */
pub fn generate_totp_code_at(secret_input: &str, timestamp: u64) -> Result<TotpResponse, String> {
    let clean_secret = parse_otpauth_uri(secret_input)?;

    let secret_bytes = Secret::Encoded(clean_secret)
        .to_bytes()
        .map_err(|e| format!("Error decodificando secreto Base32: {:?}", e))?;

    let totp = TOTP::new_unchecked(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        "".to_string(),
    );

    let code = totp.generate(timestamp);
    let step = 30u64;
    let seconds_remaining = (step - (timestamp % step)) as u8;

    Ok(TotpResponse {
        code,
        seconds_remaining,
    })
}

/**
 * Genera el código TOTP actual y segundos restantes usando la hora del reloj del sistema.
 */
pub fn generate_totp_code(secret_input: &str) -> Result<TotpResponse, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Error de reloj del sistema: {}", e))?
        .as_secs();

    generate_totp_code_at(secret_input, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector de prueba oficial de RFC 6238:
    // Secreto ASCII: "12345678901234567890" (20 bytes)
    // En Base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    const RFC_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_rfc6238_test_vectors() {
        let res59 = generate_totp_code_at(RFC_SECRET_BASE32, 59).unwrap();
        assert_eq!(res59.code, "287082");
        assert_eq!(res59.seconds_remaining, 1);

        let res_1109 = generate_totp_code_at(RFC_SECRET_BASE32, 1111111109).unwrap();
        assert_eq!(res_1109.code, "081804");
        assert_eq!(res_1109.seconds_remaining, 1);

        let res_1111 = generate_totp_code_at(RFC_SECRET_BASE32, 1111111111).unwrap();
        assert_eq!(res_1111.code, "050471");
        assert_eq!(res_1111.seconds_remaining, 29);

        let res_1234 = generate_totp_code_at(RFC_SECRET_BASE32, 1234567890).unwrap();
        assert_eq!(res_1234.code, "005924");
        assert_eq!(res_1234.seconds_remaining, 30);

        let res_2000 = generate_totp_code_at(RFC_SECRET_BASE32, 2000000000).unwrap();
        assert_eq!(res_2000.code, "279037");
        assert_eq!(res_2000.seconds_remaining, 10);
    }

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed, "JBSWY3DPEHPK3PXP");

        let raw = "  jbsw y3dp-ehpk 3pxp  ";
        let parsed2 = parse_otpauth_uri(raw).unwrap();
        assert_eq!(parsed2, "JBSWY3DPEHPK3PXP");

        assert!(parse_otpauth_uri("otpauth://totp/Test?issuer=Test").is_err());
        assert!(parse_otpauth_uri("invalid base 32 890!").is_err());
        assert!(parse_otpauth_uri("").is_err());
    }
}
