# mplock-core

Núcleo criptográfico, motor de almacenamiento de bóvedas y utilidades de seguridad para el gestor de contraseñas **MPLock**, desarrollado en Rust.

`mplock-core` está diseñado para ser un crate completamente independiente, desacoplado de interfaces de usuario (Tauri, Electron, Web), de plataformas específicas y de infraestructura comercial.

---

## 🚀 Características incluidas

### 1. Cifrado y Descifrado de Bóvedas (`mplock_core::crypto`)
- **Algoritmo de cifrado:** AES-256-GCM (cifrado autenticado con verificación de integridad mediante authentication tag).
- **Derivación de claves:** PBKDF2-HMAC-SHA256 con **600,000 iteraciones** de acuerdo con las recomendaciones OWASP actuales.
- **Formato del payload cifrado:** Empaquetado binario serializado en Base64:
  `[Salt (16 bytes)] + [Nonce/IV (12 bytes)] + [Ciphertext + Auth Tag (Variable)]`
- **Higiene de memoria:** Uso de la trait `Zeroize` para sobrescribir claves maestras, DEKs temporales y buffers en memoria RAM al ser liberados.

### 2. Gestión de Almacenamiento y Bóveda Segura (`mplock_core::storage`)
- **Arquitectura de Clave Envoltorio (DEK - Data Encryption Key):**
  - Generación de un DEK aleatorio de 32 bytes (256 bits).
  - El DEK se almacena cifrado dos veces de forma independiente:
    1. Cifrado con la contraseña maestra del usuario.
    2. Cifrado con un código de recuperación humanamente legible.
- **Códigos de recuperación:** Generación de códigos de 24 caracteres aleatorios formateados en bloques (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`), excluyendo caracteres visualmente ambiguos (`0`, `O`, `1`, `I`).
- **Migración transparente:** Soporte de actualización automática de esquemas legados hacia el esquema envoltorio con UUIDs persistentes.
- **Modelos de datos:** Estructura `Credential` con campo `id` persistente y secreto TOTP opcional.

### 3. Generador de Contraseñas Criptográficamente Seguras (`mplock_core::password`)
- Generador respaldado por el CSPRNG del sistema operativo (`rand::rngs::OsRng`).
- **Muestreo de rechazo (Rejection Sampling):** Selección 100% uniforme e independiente sobre 78 caracteres legibles (alfabeto latino minúsculas/mayúsculas, números y símbolos).
- **Cero sesgo de módulo (Zero modulo bias):** Garantiza que cada contraseña generada contenga obligatoriamente al menos una minúscula, una mayúscula, un dígito y un carácter especial.

### 4. Motor de Autenticación 2FA / TOTP (`mplock_core::totp`)
- **Estándar RFC 6238:** Generación de códigos TOTP de 6 dígitos basados en HMAC-SHA1 y ventanas temporales de 30 segundos.
- **Cálculo de caducidad:** Cálculo preciso de segundos restantes en la ventana temporal actual.
- **Normalización de secretos Base32:** Limpieza de espacios, guiones y conversión a mayúsculas con validación estricta del alfabeto RFC 4648.
- **Parser de URIs:** Extracción automática de secretos a partir de esquemas estándar `otpauth://totp/...`.

### 5. Mecanismo Criptográfico Genérico de Verificación Ed25519 (`mplock_core::license`)
- **Verificación offline de licencias:** Validación puramente criptográfica de firmas Ed25519 sobre payloads binarios compactos de 14 bytes (versión, plan, timestamps UNIX y hash de identidad).
- **Lista de revocación criptográfica:** Verificación de huellas SHA-256 de firmas revocadas.
- **Cero acoplamiento comercial:** La biblioteca no contiene claves públicas ni listas de revocación propietarias hardcodeadas; estas son suministradas por el consumidor de la API.

---

## 🚫 Qué NO incluye este crate (Diseño deliberado)

Para preservar la pureza, seguridad e independencia del núcleo, este crate **NO** incluye:
- ❌ **Dependencias de Tauri ni de GUI:** No depende de Tauri, Wry, Webview ni librerías de interfaz gráfica.
- ❌ **Integración comercial con pasarelas de pago:** No contiene SDKs ni lógica vinculada a Lemon Squeezy, Stripe, Gumroad ni webhooks externos.
- ❌ **Claves privadas:** Ninguna clave privada o de firma reside en el código fuente.
- ❌ **Claves públicas comerciales propietarias:** El verificador de licencias recibe la clave pública como parámetro `&[u8; 32]`, permitiendo el uso de cualquier par de claves.
- ❌ **Lógica específica de modelo de negocio:** Reglas comerciales particulares (como límites de cuentas gratuitas o días de prueba) deben residir en la aplicación consumidora.
- ❌ **Huellas de hardware del sistema operativo:** No realiza lecturas directas del registro de Windows (`winreg`), WMI ni llamadas propietarias de SO.

---

## 📦 Uso rápido

Agrega `mplock-core` a tu `Cargo.toml`:

```toml
[dependencies]
mplock-core = { version = "0.1.0" }
```

### Ejemplo: Cifrado y descifrado de datos
```rust
use mplock_core::crypto;

let password = b"MiPasswordMaestroSuperSeguro123!";
let data = "Información confidencial de la bóveda";

// Cifrar con AES-256-GCM + PBKDF2 (600k iteraciones)
let payload_b64 = crypto::encrypt(data, password)?;

// Descifrar verificando autenticidad
let decrypted = crypto::decrypt(&payload_b64, password)?;
assert_eq!(decrypted, data);
```

### Ejemplo: Generación de contraseñas
```rust
use mplock_core::password;

// Genera una contraseña segura de 20 caracteres garantizando todas las clases
let secure_pass = password::generate_secure_password(20)?;
println!("Contraseña generada: {}", secure_pass);
```

### Ejemplo: Generación de códigos TOTP / 2FA
```rust
use mplock_core::totp;

let secret = "JBSWY3DPEHPK3PXP";
let response = totp::generate_totp_code(secret)?;

println!("Código 2FA: {}", response.code);
println!("Segundos restantes: {}", response.seconds_remaining);
```

### Ejemplo: Verificación criptográfica de licencia Ed25519
```rust
use mplock_core::license;

let public_key: [u8; 32] = [/* 32 bytes de tu clave pública Ed25519 */];
let revoked_hashes: &[&str] = &[]; // Lista de hashes SHA-256 revocados

let license_key = "AEAWR-PSFEA-...";
let payload = license::verify_license(license_key, &public_key, revoked_hashes)?;

println!("Plan: {}", payload.plan);
println!("Emitida en timestamp: {}", payload.issued_at);
```

---

## 🧪 Ejecución de Tests

`mplock-core` incluye una suite completa de pruebas unitarias que cubren vectores de prueba oficiales (RFC 6238 para TOTP, vectores de cifrado y muestreo de contraseñas):

```bash
cargo test -p mplock-core
```

---

## ⚖️ Licencia

Este proyecto está distribuido bajo licencia dual, a elección del usuario:
- **Licencia MIT** ([LICENSE-MIT](LICENSE-MIT))
- **Licencia Apache 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

Esta dualidad es el estándar de facto en el ecosistema Rust (como Serde y Tokio), permitiendo tanto la máxima permisividad para proyectos de código abierto (MIT) como la protección explícita de patentes requerida por entornos corporativos (Apache-2.0).
