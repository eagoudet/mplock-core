use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;

use crate::crypto;

/**
 * Genera un UUID v4 por defecto para identificar de forma única una credencial.
 */
pub fn default_credential_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/**
 * Modelo de datos para las credenciales individuales.
 * Implementa Zeroize para sobreescribir la memoria en RAM al destruirse el objeto.
 */
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Credential {
    #[serde(default = "default_credential_id")]
    pub id: String,
    pub system: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
}

/**
 * Representa la estructura de la bóveda cifrada en disco.
 */
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vault {
    pub encrypted_credentials: String,
    pub encrypted_dek_master: String,
    pub encrypted_dek_recovery: String,
}

/**
 * Métodos de autenticación posibles para desbloquear la bóveda.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    MasterPassword,
    RecoveryCode,
    OldFormat,
}

/**
 * Contenedor devuelto tras un desbloqueo exitoso de la bóveda.
 */
pub struct UnlockedVault {
    pub credentials: Vec<Credential>,
    pub dek: Vec<u8>,
    pub unlock_method: UnlockMethod,
    pub recovery_code: Option<String>, // Presente si se requirió migración del formato antiguo
}

/**
 * Genera un código de recuperación legible de 24 caracteres aleatorios (6 bloques de 4),
 * excluyendo caracteres ambiguos (O, 0, I, 1) para evitar confusiones al transcribirlo.
 */
pub fn generate_recovery_code() -> String {
    let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 caracteres legibles
    let mut rng = OsRng;
    let mut code = String::with_capacity(29);
    for i in 0..24 {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        let idx = rng.gen_range(0..chars.len());
        code.push(chars[idx] as char);
    }
    code
}

/**
 * Crea e inicializa una nueva bóveda en disco.
 * Genera una DEK aleatoria (Data Encryption Key de 32 bytes) y la cifra
 * tanto con la contraseña maestra como con el código de recuperación provisto.
 */
pub fn initialize_db(
    db_path: &Path,
    master_password: &[u8],
    recovery_code: &str,
) -> Result<Vec<u8>, String> {
    // 1. Generar DEK aleatorio (32 bytes)
    let mut dek = vec![0u8; 32];
    OsRng.fill_bytes(&mut dek);

    // 2. Codificar DEK en Base64 para guardarlo envuelto
    let dek_base64 = general_purpose::STANDARD.encode(&dek);

    // 3. Cifrar el DEK con la contraseña maestra
    let encrypted_dek_master = crypto::encrypt(&dek_base64, master_password)?;

    // 4. Cifrar el DEK con el código de recuperación (limpiando guiones)
    let cleaned_recovery = recovery_code.replace('-', "");
    let encrypted_dek_recovery = crypto::encrypt(&dek_base64, cleaned_recovery.as_bytes())?;

    // 5. Cifrar una lista vacía de credenciales inicialmente con el DEK
    let encrypted_credentials = crypto::encrypt("[]", &dek)?;

    let vault = Vault {
        encrypted_credentials,
        encrypted_dek_master,
        encrypted_dek_recovery,
    };

    // 6. Guardar en disco
    let mut file = File::create(db_path)
        .map_err(|e| format!("No se pudo crear el archivo de base de datos: {}", e))?;
    let vault_json = serde_json::to_string(&vault)
        .map_err(|e| format!("Error al serializar la bóveda: {}", e))?;
    file.write_all(vault_json.as_bytes())
        .map_err(|e| format!("Error al escribir los datos en disco: {}", e))?;

    Ok(dek)
}

/**
 * Carga y descifra la base de datos de credenciales desde el disco.
 * Soporta migración transparente desde el formato legacy de cifrado directo.
 */
pub fn load_db(db_path: &Path, password: &[u8]) -> Result<UnlockedVault, String> {
    if !db_path.exists() {
        return Err("La base de datos no existe".to_string());
    }

    let mut file = File::open(db_path)
        .map_err(|e| format!("No se pudo abrir la base de datos: {}", e))?;

    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .map_err(|e| format!("No se pudo leer la base de datos: {}", e))?;

    let file_content = file_content.trim();

    // Comprobar si es el formato JSON con DEK envuelto
    if file_content.starts_with('{') {
        let vault: Vault = serde_json::from_str(file_content)
            .map_err(|e| format!("Error decodificando el Vault: {}", e))?;

        // 1. Intentar descifrar el DEK usando la clave maestra provista
        let (mut dek_str, unlock_method) = match crypto::decrypt(&vault.encrypted_dek_master, password) {
            Ok(decrypted) => (decrypted, UnlockMethod::MasterPassword),
            Err(_) => {
                // 2. Si falla, intentar limpiar guiones y usar como código de recuperación
                let cleaned_pass_str = String::from_utf8_lossy(password).replace('-', "");
                match crypto::decrypt(&vault.encrypted_dek_recovery, cleaned_pass_str.as_bytes()) {
                    Ok(decrypted) => (decrypted, UnlockMethod::RecoveryCode),
                    Err(_) => {
                        return Err("Contraseña maestra o código de recuperación incorrectos".to_string());
                    }
                }
            }
        };

        // 3. Decodificar el DEK desde su formato Base64
        let dek = general_purpose::STANDARD
            .decode(&dek_str)
            .map_err(|e| format!("Error decodificando DEK desde Base64: {}", e))?;

        dek_str.zeroize(); // Limpieza inmediata de memoria

        // 4. Descifrar credenciales reales con el DEK
        let json_str = crypto::decrypt(&vault.encrypted_credentials, &dek)?;

        // Deserializar credenciales
        let credentials: Vec<Credential> = serde_json::from_str(&json_str)
            .map_err(|e| format!("Error al decodificar credenciales: {}", e))?;

        // Comprobar si alguna credencial provenía del formato anterior sin UUID persistido en disco
        let needs_id_migration = match serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
            Ok(values) => values.iter().any(|v| v.get("id").is_none()),
            Err(_) => false,
        };

        if needs_id_migration {
            // Persistir inmediatamente los nuevos UUIDs generados en disco para garantizar estabilidad
            let _ = save_db(db_path, &credentials, &dek);
        }

        Ok(UnlockedVault {
            credentials,
            dek,
            unlock_method,
            recovery_code: None,
        })
    } else {
        // Formato legacy: Cifrado directo con la contraseña maestra
        let json_str = crypto::decrypt(file_content, password)?;

        let credentials: Vec<Credential> = serde_json::from_str(&json_str)
            .map_err(|e| format!("Error al decodificar JSON del formato anterior: {}", e))?;

        // Iniciar proceso de migración automática
        let recovery_code = generate_recovery_code();

        // Generar nuevo DEK de 32 bytes
        let mut dek = vec![0u8; 32];
        OsRng.fill_bytes(&mut dek);

        let dek_base64 = general_purpose::STANDARD.encode(&dek);

        // Cifrar el DEK con la contraseña maestra
        let encrypted_dek_master = crypto::encrypt(&dek_base64, password)?;

        // Cifrar el DEK con el código de recuperación
        let cleaned_recovery = recovery_code.replace('-', "");
        let encrypted_dek_recovery = crypto::encrypt(&dek_base64, cleaned_recovery.as_bytes())?;

        // Cifrar credenciales con el nuevo DEK
        let migrated_creds_json = serde_json::to_string(&credentials)
            .map_err(|e| format!("Error al serializar credenciales migradas: {}", e))?;
        let encrypted_credentials = crypto::encrypt(&migrated_creds_json, &dek)?;

        let migrated_vault = Vault {
            encrypted_credentials,
            encrypted_dek_master,
            encrypted_dek_recovery,
        };

        // Guardar el nuevo formato en disco
        let mut file = File::create(db_path)
            .map_err(|e| format!("No se pudo migrar la base de datos: {}", e))?;
        let vault_json = serde_json::to_string(&migrated_vault)
            .map_err(|e| format!("Error al serializar la bóveda migrada: {}", e))?;
        file.write_all(vault_json.as_bytes())
            .map_err(|e| format!("Error al guardar la bóveda migrada: {}", e))?;

        Ok(UnlockedVault {
            credentials,
            dek,
            unlock_method: UnlockMethod::OldFormat,
            recovery_code: Some(recovery_code),
        })
    }
}

/**
 * Serializa, cifra y escribe las credenciales en la base de datos usando el DEK.
 * Mantiene intactas las claves envueltas existentes en el archivo.
 */
pub fn save_db(db_path: &Path, credentials: &[Credential], dek: &[u8]) -> Result<(), String> {
    if !db_path.exists() {
        return Err("No se puede guardar: la base de datos no existe".to_string());
    }

    // 1. Serializar credenciales a JSON
    let json_str = serde_json::to_string(credentials)
        .map_err(|e| format!("Error al generar JSON: {}", e))?;

    // 2. Cifrar con el DEK
    let encrypted_payload = crypto::encrypt(&json_str, dek)?;

    // 3. Cargar la bóveda actual del disco para leer los DEKs envueltos
    let mut file = File::open(db_path)
        .map_err(|e| format!("No se pudo abrir la base de datos para guardar: {}", e))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("No se pudo leer la base de datos para guardar: {}", e))?;

    let mut vault: Vault = serde_json::from_str(&content)
        .map_err(|e| format!("La base de datos tiene un formato inválido en disco: {}", e))?;

    // 4. Actualizar credenciales cifradas únicamente
    vault.encrypted_credentials = encrypted_payload;

    // 5. Guardar de nuevo en el disco
    let mut file = File::create(db_path)
        .map_err(|e| format!("No se pudo abrir la base de datos para guardar: {}", e))?;
    let vault_json = serde_json::to_string(&vault)
        .map_err(|e| format!("Error al serializar la bóveda actualizada: {}", e))?;
    file.write_all(vault_json.as_bytes())
        .map_err(|e| format!("Error al escribir los datos en disco: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_recovery_code_generation_format() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), 29); // 24 chars + 5 dashes
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert_eq!(part.len(), 4);
            // No ambiguous characters
            assert!(!part.contains('O'));
            assert!(!part.contains('0'));
            assert!(!part.contains('I'));
            assert!(!part.contains('1'));
        }
    }

    #[test]
    fn test_initialize_and_load_db_with_master_and_recovery() {
        let temp_dir = std::env::temp_dir().join(format!("mplock_core_test_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("test_vault.enc");

        let master_pass = b"TestMasterPass123!";
        let recovery_code = generate_recovery_code();

        // 1. Inicializar
        let original_dek = initialize_db(&db_path, master_pass, &recovery_code).expect("Init failed");
        assert_eq!(original_dek.len(), 32);

        // 2. Desbloquear con contraseña maestra
        let unlocked_master = load_db(&db_path, master_pass).expect("Load with pass failed");
        assert_eq!(unlocked_master.unlock_method, UnlockMethod::MasterPassword);
        assert_eq!(unlocked_master.dek, original_dek);
        assert_eq!(unlocked_master.credentials.len(), 0);

        // 3. Desbloquear con código de recuperación (con guiones)
        let unlocked_recov = load_db(&db_path, recovery_code.as_bytes()).expect("Load with recovery code failed");
        assert_eq!(unlocked_recov.unlock_method, UnlockMethod::RecoveryCode);
        assert_eq!(unlocked_recov.dek, original_dek);

        // 4. Guardar credenciales y recargar
        let new_cred = Credential {
            id: default_credential_id(),
            system: "example.com".to_string(),
            username: "alice".to_string(),
            password: "SecretPassword!".to_string(),
            notes: "Test note".to_string(),
            totp_secret: None,
        };
        save_db(&db_path, &[new_cred.clone()], &original_dek).expect("Save failed");

        let reloaded = load_db(&db_path, master_pass).expect("Reload failed");
        assert_eq!(reloaded.credentials.len(), 1);
        assert_eq!(reloaded.credentials[0].system, "example.com");
        assert_eq!(reloaded.credentials[0].username, "alice");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
