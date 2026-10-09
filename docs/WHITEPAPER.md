# Whitepaper de Arquitectura Criptográfica: MPLock & mplock-core

**Documento Técnico Oficial — Versión 1.4 (Octubre 2026)**  
**Ámbito de Referencia:** `mplock-core` v0.1.1 (en `main`) · `MPLock Desktop` v1.4.0 (Windows x64) · `Extensiones` v1.10.0  
**Repositorio Abierto del Núcleo:** [github.com/eagoudet/mplock-core](https://github.com/eagoudet/mplock-core)  
**Licencia del Núcleo:** MIT OR Apache-2.0  

---

## 1. Resumen Ejecutivo / Executive Summary

### Resumen Ejecutivo (Español)
MPLock es un gestor de credenciales y autenticador de doble factor (2FA/TOTP) concebido para el sistema operativo Microsoft Windows bajo los principios de control soberano de los datos y procesamiento estrictamente local (*local-first*). A diferencia de los modelos dependientes de nubes centralizadas, en MPLock la base de datos de credenciales reside en el almacenamiento local del equipo del usuario y no es transferida a servidores remotos ni a infraestructuras en la nube.

El núcleo criptográfico subyacente, implementado en la biblioteca abierta `mplock-core` escrita en Rust, utiliza un esquema de sobre cerrado con Clave de Cifrado de Datos (DEK, *Data Encryption Key*) de 256 bits generada mediante el generador criptográfico del sistema operativo (`OsRng`). Los datos confidenciales se cifran con el algoritmo autenticado AES-256-GCM (nonce aleatorio de 96 bits con probabilidad de colisión despreciable), mientras que la DEK se almacena envuelta de forma independiente bajo dos derivaciones: la contraseña maestra del usuario y un código de recuperación humanamente legible de 24 caracteres (alfabeto Crockford Base32 de 32 símbolos, equivalente a 120 bits de entropía). Cada derivación aplica la función estándar PBKDF2-HMAC-SHA256 con 600.000 iteraciones y sales criptográficas únicas de 16 bytes.

El presente documento expone una descripción técnica, honesta y contrastable del diseño criptográfico del software, delimitando tanto las garantías que ofrece frente al robo o extracción de datos en reposo, como sus fronteras y limitaciones intrínsecas frente a entornos operativos adversos o terminales comprometidos.

### Executive Summary (English)
MPLock is a local-first password manager and time-based one-time password (TOTP/2FA) authenticator engineered for Microsoft Windows to ensure sovereign local data control. Unlike cloud-dependent alternatives, user credentials stored in MPLock reside exclusively within the local file system and are never synchronized or transmitted to remote infrastructure.

The core cryptographic engine, encapsulated in the standalone, open-source Rust library `mplock-core`, employs an envelope encryption model anchored by a 256-bit Data Encryption Key (DEK) generated via the operating system's CSPRNG (`OsRng`). Vault payloads are encrypted using authenticated AES-256-GCM with a 96-bit random nonce. The DEK itself is wrapped twice independently: once under the user's master password and once under a 24-character human-readable recovery code (Crockford Base32 alphabet of 32 symbols, providing 120 bits of entropy). Both key wrapping operations utilize PBKDF2-HMAC-SHA256 with 600,000 iterations and distinct 16-byte random salts.

This whitepaper provides a detailed, verifiable, and transparent technical description of MPLock's cryptographic architecture. Every architectural claim is referenced to actual source files. The document explicitly delineates the security boundaries of the system, stating what MPLock protects against in offline scenarios, as well as the inherent limitations of any software running on a compromised host operating system.

---

## 2. Alcance y Modelo de Amenazas

Un diseño de seguridad responsable exige definir con rigor el límite entre las amenazas mitigadas por el modelo criptográfico y los vectores de ataque que quedan fuera de su control. MPLock Desktop es una aplicación diseñada y distribuida exclusivamente para **Microsoft Windows (x64)**.

```
+--------------------------------------------------------------------------------+
|                             SISTEMA OPERATIVO HOST (WINDOWS)                   |
|                                                                                |
|  [ VECTORES FUERA DE CONTROL: Malware, Keyloggers, Memoria en Ejecución ]      |
|                                                                                |
|       +-----------------------------------------------------------------+      |
|       |                     PROCESO MPLOCK (RUST)                       |      |
|       |                                                                 |      |
|       |   Contraseña Maestra en RAM  -----> [ mitigación zeroize ]      |      |
|       |   DEK efímero (32 bytes)     -----> [ mitigación zeroize ]      |      |
|       +-----------------------------------------------------------------+      |
|                                        |                                       |
|                                        |  Cifrado AES-256-GCM                  |
|                                        v  PBKDF2 (600.000 iteraciones)         |
|       +-----------------------------------------------------------------+      |
|       |                  DISCO LOCAL / ALMACÉN EN REPOSO                |      |
|       |                                                                 |      |
|       |   credentials.enc:                                              |      |
|       |   [ DEK envuelto (Master) ] [ DEK envuelto (Recovery) ]         |      |
|       |   [ Payload cifrado de credenciales con DEK + Auth Tag ]        |      |
|       +-----------------------------------------------------------------+      |
|                                                                                |
|  [ VECTOR MITIGADO: Robo del archivo en reposo o extracción de disco ]         |
+--------------------------------------------------------------------------------+
```

### 2.1 Qué Protege MPLock
* **Robo o filtración del archivo de bóveda en reposo (`credentials.enc`):** Si un atacante extrae físicamente el disco duro, copia la carpeta de datos de la aplicación (`%APPDATA%/com.passwords.app/credentials.enc`) o accede a una copia de seguridad sin autorización, los datos permanecen computacionalmente inviables de descifrar sin el conocimiento previo de la contraseña maestra (con entropía adecuada) o del código de recuperación alfanumérico.
* **Manipulación y corrupción de datos cifrados:** El uso de AES-256-GCM incorpora un tag de autenticación de 128 bits que permite la detección criptográfica inmediata de cualquier bit alterado, truncado o inyectado en el archivo de la bóveda antes de que los datos puedan ser procesados.
* **Coste computacional ante fuerza bruta:** La derivación de claves mediante 600.000 iteraciones de PBKDF2-HMAC-SHA256 eleva sustancialmente el coste de tiempo de cómputo en ataques de diccionario y fuerza bruta en CPU.

### 2.2 Lo que MPLock NO Protege (Límites Explícitos de Seguridad)
Ningún gestor de contraseñas de software puede sustituir las garantías fundamentales de un sistema operativo seguro. MPLock declara de forma transparente que **no protege ni puede proteger** frente a los siguientes escenarios:
1. **Malware, troyanos o *keyloggers* activos en el equipo:** Si el dispositivo anfitrión contiene software espía capaz de interceptar eventos del teclado (`GetKeyState`, hooks globales de teclado en Windows) o capturar la pantalla, la contraseña maestra puede ser obtenida en el instante exacto en que el usuario la teclea.
2. **Lectura de memoria por otros procesos del mismo usuario:** En Windows, cualquier proceso o script que se ejecute bajo la misma sesión de usuario interactiva y con el mismo nivel de integridad puede, en general, abrir el proceso de MPLock mediante `OpenProcess(PROCESS_VM_READ)` y examinar su espacio de direcciones virtuales sin requerir privilegios de Administrador local ni elevación UAC. Mientras la bóveda permanece desbloqueada, los datos descifrados residen en la memoria RAM del proceso.
3. **Contraseña maestra débil o predecible:** Un usuario que escoja una contraseña maestra corta, predecible o presente en filtraciones masivas anula la protección de PBKDF2.
4. **Pérdida simultánea de contraseña y código de recuperación:** Dado que MPLock opera sin servidores ni mecanismos de custodia de claves, **no existe recuperación posible**. Si el usuario olvida su clave y pierde su código físico de recuperación, los datos se pierden irreversiblemente.
5. **Limpieza de Portapapeles y Mitigación de Historial en Windows:** Al copiar una credencial o secreto, MPLock utiliza las extensiones nativas de Windows en `arboard` (`SetExtWindows::exclude_from_history()` y `exclude_from_cloud()`, `src-tauri/src/lib.rs`), instruyendo al sistema operativo para que no registre el secreto en el Historial del Portapapeles (`Win + V`) ni lo sincronice en la nube de Microsoft. Estas directivas son respetadas por Windows y por gestores de portapapeles bien portados, pero no necesariamente por herramientas de terceros no conformes. Asimismo, un temporizador en segundo plano vacía el portapapeles tras 30 segundos si el contenido aún coincide con el secreto copiado (función pura `should_clear_clipboard`). En un cierre normal de la aplicación, el manejador de eventos del ciclo de vida (`tauri::WindowEvent::CloseRequested / Destroyed`) intercepta el cierre y limpia inmediatamente el portapapeles si todavía contiene el secreto; no obstante, un cierre forzado del proceso (ej. `taskkill` o Administrador de tareas), un apagado repentino del equipo o un fallo imprevisto pueden impedir dicha ejecución y dejar el secreto en el portapapeles del sistema. La limpieza automática a los 30 segundos y la exclusión del historial de Windows (Win+V) se aplican a las copias hechas desde la aplicación de escritorio. El botón de copiar el código TOTP del popup de la extensión del navegador usa el portapapeles del navegador: ese valor no se limpia automáticamente ni se excluye del historial de Windows.
6. **Custodia de Credenciales en la Memoria del Navegador:** Cuando las credenciales se transfieren a la extensión web para autorrellenar un formulario, residen temporalmente en la memoria del navegador (motor JavaScript/V8). MPLock no puede forzar una sobrescritura con ceros (`zeroize`) en la memoria del navegador debido a que el recolector de basura de JavaScript maneja cadenas inmutables y el ciclo de vida de la memoria del navegador es ajeno al proceso de escritorio.
7. **Ataques de Reversión (Rollback):** AES-256-GCM comprueba la autenticidad del archivo que se está descifrando, pero **no previene ataques de reversión (rollback)**. Si un atacante sustituye el archivo de la bóveda actual por una copia de respaldo legítima anterior, MPLock la descifrará con éxito sin alertar de que los datos han sido revertidos a un estado anterior, al no contar con un contador monótono en hardware (como TPM).
8. **Consolidación de Contraseñas y Semillas 2FA en el mismo almacén:** Almacenar contraseñas y semillas secretas TOTP en la misma base de datos rompe el principio de segundo factor fuera de banda (*out-of-band*). Si la bóveda se ve vulnerada, ambos factores de autenticación quedan expuestos de forma simultánea.
9. **Integridad de un sistema operativo comprometido:** Modificaciones maliciosas en las DLLs de sistema, el registro de Windows o los binarios locales de MPLock escapan al perímetro de defensa de la aplicación.

---

## 3. Arquitectura Criptográfica de la Bóveda

La gestión del almacenamiento cifrado en disco está implementada en los módulos `crypto.rs` y `storage.rs` de `mplock-core`.

```
                            [ Contraseña Maestra ]            [ Código de Recuperación ]
                                      |                                  |
                                      v                                  v
                               PBKDF2-HMAC-SHA256                 PBKDF2-HMAC-SHA256
                                600.000 rondas                     600.000 rondas
                               Salt único 16B                     Salt único 16B
                                      |                                  |
                                      v                                  v
                             Clave KEK_Master                   Clave KEK_Recovery
                                 (32 bytes)                         (32 bytes)
                                      \                                  /
                                       \                                /
                                        v                              v
                                  AES-256-GCM                    AES-256-GCM
                                 Nonce 12B indiv.               Nonce 12B indiv.
                                        \                              /
                                         v                            v
                                    [ DEK envuelto ]            [ DEK envuelto ]
                                    (encrypted_dek_master)      (encrypted_dek_recovery)
                                                  \            /
                                                   \          /
                                                    v        v
                                                 [ DEK descifrado ]
                                                    (32 bytes)
                                                         |
                                                         v
                                                    AES-256-GCM
                                                  Nonce único 12B
                                                         |
                                                         v
                                             [ encrypted_credentials ]
                                             (Array JSON de Credenciales)
```

### 3.1 Esquema de Clave de Datos Dual (DEK Envelope Encryption)
* **Generación de la DEK:** Al inicializar la bóveda (`storage::initialize_db`, `storage.rs:89-97`), se genera una clave simétrica aleatoria de 256 bits (32 bytes) denominada *Data Encryption Key* (DEK) utilizando el generador del sistema `rand::rngs::OsRng`.
* **Cifrado de la DEK:** La DEK se codifica temporalmente en Base64 (`storage.rs:99`) y se cifra dos veces de forma independiente bajo dos claves maestras de cifrado de clave (*Key Encryption Keys*, KEK):
  1. `encrypted_dek_master`: Cifrado con la contraseña maestra ingresada por el usuario (`storage.rs:102`).
  2. `encrypted_dek_recovery`: Cifrado con el código alfanumérico de recuperación de 24 caracteres sin guiones (`storage.rs:104-106`).
* **Cifrado del Contenido:** Las credenciales en formato JSON (`Vec<Credential>`) se cifran exclusivamente con la DEK mediante AES-256-GCM (`storage.rs:109, 252-263`).
* **Ventaja Arquitectónica:** Este modelo desacopla la clave que protege los registros de la clave que introduce el usuario. Cuando el usuario cambia su contraseña maestra o regenera su código de recuperación, **no se requiere volver a cifrar todos los registros de la base de datos**; basta con re-envolver la DEK con la nueva clave derivada (`src-tauri/src/lib.rs:408-456, 459-508` — componente de escritorio cerrado).

### 3.2 Cifrado Autenticado AES-256-GCM
* **Primitiva:** `aes_gcm::Aes256Gcm` del proyecto RustCrypto (`crypto.rs:1-4`).
* **Tamaño del Nonce / Vector de Inicialización (IV):** Exactamente 12 bytes (96 bits) (`crypto.rs:15`, constante `IV_LEN = 12`).
* **Generación del Nonce:** En cada operación individual de cifrado (`crypto::encrypt`, `crypto.rs:31-65`), se genera un nonce aleatorio de 96 bits mediante `OsRng.fill_bytes(&mut iv)` (`crypto.rs:41-42`). Para el volumen esperado de operaciones de un usuario personal, la probabilidad de colisión aleatoria de nonces de 96 bits es estadísticamente despreciable.
* **Autenticación e Integridad:** AES-GCM produce un tag de autenticación de 16 bytes (128 bits) concatenado al final del texto cifrado (`ciphertext`). Durante el descifrado (`crypto::decrypt`, `crypto.rs:98-100`), la biblioteca verifica que el tag coincida antes de procesar el texto plano.

### 3.3 Función de Derivación de Claves (PBKDF2) y Análisis Comparativo
* **Algoritmo:** PBKDF2 parametrizado con `SimpleHmac<Sha256>` (`crypto.rs:6, 10, 21-24`).
* **Iteraciones:** `PBKDF2_ITERATIONS = 600_000` (`crypto.rs:13`), alineado con las recomendaciones actuales de OWASP.
* **Salt Criptográfico:** 16 bytes (128 bits) (`crypto.rs:14`, constante `SALT_LEN = 16`). En cada cifrado se genera un salt nuevo con `OsRng.fill_bytes(&mut salt)` (`crypto.rs:33-34`).
* **Limitación Arquitectónica (PBKDF2 frente a Argon2id):** PBKDF2 eleva sustancialmente el coste temporal frente a ataques de fuerza bruta basados en CPU, pero **no es un algoritmo duro en memoria (*memory-hard*)**. Algoritmos modernos como **Argon2id** o **scrypt** ofrecen una resistencia sensiblemente superior contra adversarios equipados con granjas masivas de GPUs, FPGAs o ASICs dedicados debido a que exigen un uso intensivo de ancho de banda y memoria RAM. La ausencia de Argon2id es una limitación conocida de la versión 1.x.

### 3.4 Estructura del Archivo de Bóveda (`credentials.enc`)
El archivo de almacenamiento en disco es un documento JSON estructurado según el struct `Vault` (`storage.rs:40-44`):
```json
{
  "encrypted_credentials": "<Base64_Payload>",
  "encrypted_dek_master": "<Base64_Payload>",
  "encrypted_dek_recovery": "<Base64_Payload>"
}
```
Cada uno de los tres campos almacena un payload binario serializado en Base64 estándar (`crypto.rs:27-30, 58-64`):
```
+------------------------------------------------------------------------+
|                              PAYLOAD BASE64                            |
+------------------------------------+------------------+----------------+
|          Salt (16 bytes)           |   IV (12 bytes)  |  Ciphertext +  |
|                                    |                  |  Tag (var.)    |
+------------------------------------+------------------+----------------+
```
Durante el desbloqueo (`storage::load_db`, `storage.rs:132-196`), el sistema extrae los primeros 16 bytes como Salt, los siguientes 12 como IV, y entrega el remanente a `Aes256Gcm::decrypt`.

### 3.5 Especificación del Formato de Respaldo Cifrado (`.mplockbackup`)
La exportación de respaldo cifrado (implementada en `src-tauri/src/lib.rs`) genera un archivo binario autónomo estructurado en dos regiones: un encabezado canónico de 30 bytes seguido del payload cifrado con el motor de `mplock-core`:
* **Encabezado Binario (30 bytes en Little-Endian):**
  1. `Magic Bytes` (14 bytes): Cadena ASCII fija `MPLOCK_BACKUP\0` (identificador estricto de formato).
  2. `Version` (4 bytes, `u32` LE): Versión del formato (fijada en `1`; versiones superiores son rechazadas con error explicativo).
  3. `Iterations` (4 bytes, `u32` LE): Rondas de PBKDF2 (fijadas en `600_000`; valores < 600.000 o > 2.000.000 son rechazados por seguridad).
  4. `Salt Length` (4 bytes, `u32` LE): Longitud del salt aleatorio (`16` bytes).
  5. `Nonce Length` (4 bytes, `u32` LE): Longitud del vector de inicialización / nonce (`12` bytes).
* **Payload Cifrado:** Salida de `mplock_core::crypto::encrypt` aplicada sobre la estructura JSON serializada con las credenciales, notas y semillas TOTP, utilizando AES-256-GCM y clave derivada mediante PBKDF2-HMAC-SHA256 con una contraseña de exportación independiente de la clave maestra.
* **Escritura Atómica:** El archivo se escribe en un fichero temporal en el mismo directorio (`.{nombre}.tmp.{random}`) y se renombra atómicamente al destino final tras sincronizar buffers en disco (`sync_all`).

---

## 4. Generación de Aleatoriedad y Muestreo de Contraseñas

### 4.1 Fuente de Entropía Criptográfica (`OsRng`)
MPLock se apoya en `rand::rngs::OsRng` (`crypto.rs:8`, `storage.rs:2`, `password.rs:1`) para todas las decisiones criptográficas (sales, IVs, DEK y generación de contraseñas). En el entorno objetivo de la aplicación (Windows), `OsRng` delega la obtención de aleatoriedad directamente en `BCryptGenRandom` de la API de Criptografía de Nueva Generación (CNG) del kernel de Windows. *(Nota: Las interfaces subyacentes de la biblioteca `rand` para Linux como `getrandom(2)` o macOS como `getentropy(2)` son capacidades de la librería Rust, no un soporte activo multiplataforma de la aplicación de escritorio).*

### 4.2 Eliminación del Sesgo de Módulo (*Modulo Bias*) en el Generador de Contraseñas
El generador de contraseñas (`password::generate_secure_password`, `password.rs:21-63`) utiliza un alfabeto de **78 caracteres legibles**:
* 26 letras minúsculas (`a-z`)
* 26 letras mayúsculas (`A-Z`)
* 10 dígitos numéricos (`0-9`)
* 16 símbolos especiales (`!@#$%&*()_+-=[]?`)

#### El Problema del Sesgo de Módulo Histórico
Una implementación ingenua suele seleccionar caracteres mediante la operación módulo sobre un byte aleatorio (`byte % 78`). Debido a que 256 no es divisible de forma entera por 78:
$$256 = 3 \times 78 + 22$$
Los primeros 22 caracteres del alfabeto (índices 0 a 21) tendrían 4 valores posibles de entrada ($0..21$, $78..99$, $156..177$, $234..255$), con una probabilidad teórica de $\frac{4}{256} \approx 1,5625\%$, mientras que los 56 caracteres restantes tendrían solo 3 valores posibles ($\frac{3}{256} \approx 1,1719\%$). Este sesgo representaba una asimetría estadística del 33% en favor de ciertos caracteres.

#### Solución Implementada: Muestreo Uniforme por Rechazo (Rand)
En `password.rs:44`, la selección se realiza mediante:
```rust
let idx = rng.gen_range(0..allowed_base.len());
```
La función `gen_range` de la biblioteca `rand` implementa internamente muestreo uniforme por rechazo (*rejection sampling*), descartando los enteros residuales que causan asimetría y asegurando una probabilidad idéntica e indistinguible de $\frac{1}{78}$ para cada carácter.

Adicionalmente, el generador aplica un **muestreo de rechazo a nivel de contraseña completa** (`password.rs:36-62`). En lugar de insertar forzadamente caracteres en posiciones predeterminadas (lo cual introduciría patrones estructurales detectables), genera una secuencia uniforme y verifica en un bucle:
```rust
if has_lower && has_upper && has_number && has_symbol {
    return String::from_utf8(password_chars)...;
}
```
Si la secuencia generada aleatoriamente carece de al menos un elemento de alguna de las 4 clases de caracteres, la secuencia completa es rechazada y se genera una nueva de forma no determinista.

---

## 5. Mitigación de Secretos en Memoria Volátil (`Zeroize`)

### 5.1 Implementación y Alcance
Para reducir la ventana temporal de exposición de datos confidenciales ante volcados de memoria, `mplock-core` emplea el trait `Zeroize` de la biblioteca `zeroize` (`crypto.rs:11`, `storage.rs:8`):
1. **Claves de Derivación Intermedias:** En `crypto.rs:49` y `crypto.rs:94`, los arrays de bytes `key_bytes` (que contienen la clave de 256 bits derivada por PBKDF2) invocan explícitamente `key_bytes.zeroize()` inmediatamente después de inicializar el cifrador AES-GCM.
2. **Representaciones de la DEK en Texto:** En `storage.rs:171`, la cadena temporal descifrada `dek_str` es limpiada con `dek_str.zeroize()` tras decodificar sus bytes binarios.
3. **Estructura de Credenciales:** El struct `Credential` implementa `#[derive(Zeroize)]` con el atributo `#[zeroize(drop)]` (`storage.rs:23-24`), sobrescribiendo la memoria de usuario, contraseña y notas al salir de ámbito.
4. **Contraseña Maestra en Proceso:** Tanto en la aplicación de escritorio (`src-tauri/src/lib.rs:74, 77`) como en el host nativo (`src-tauri/src/native_host.rs:77, 92, 123`), el buffer de la contraseña maestra ejecuta `pass.zeroize()` al bloquear la base de datos o terminar el subproceso.

### 5.2 Límites Técnicos Reales (Mitigación vs. Eliminación Garantizada)
MPLock utiliza el término **"mitigación de memoria"** y rechaza la expresión "eliminación garantizada de memoria". Las limitaciones técnicas identificadas son:
* **Feature `zeroize` en el crate `aes-gcm` (habilitada desde v0.1.1):** A partir de `mplock-core v0.1.1` y `src-tauri`, se habilita explícitamente la feature `features = ["zeroize"]` en `aes-gcm = "0.10"`. Esto permite que la estructura interna `Aes256Gcm`, que contiene las subclaves expandidas de AES, sobrescriba su estado interno con ceros al ejecutarse su destructor (`drop`).
* **Archivo de Paginación del SO (`pagefile.sys`):** Si Windows decide volcar páginas de memoria RAM a disco antes de que se ejecute el destructor `drop`, fragmentos de texto claro pueden persistir en el almacenamiento no volátil.
* **Registros de CPU y Optimizaciones:** Los registros intermedios de la CPU pueden haber retenido valores transitorios antes de la ejecución de las rutinas de sobrescritura.
* **Capa Webview / JavaScript:** Las credenciales mostradas en la interfaz gráfica cruzan el puente IPC hacia React y el motor V8. El recolector de basura de JavaScript gestiona cadenas inmutables que no pueden ser sobrescritas manualmente con ceros desde el código de la UI.

---

## 6. Motor de Autenticación 2FA / TOTP

El submódulo `totp.rs` implementa el estándar abierto **RFC 6238** (Time-Based One-Time Password) como componente nativo en Rust.

### 6.1 Parámetros del Algoritmo
* **Función Pseudoaleatoria (PRF):** HMAC-SHA1 (`totp.rs:85`, `Algorithm::SHA1`).
* **Longitud del Código:** 6 dígitos decimales (`totp.rs:86`).
* **Paso de Tiempo ($T_X$):** 30 segundos estándar (`totp.rs:88, 95`).
* **Cálculo del Excedente Temporal:** `seconds_remaining = 30 - (timestamp % 30)` (`totp.rs:96`).

### 6.2 Normalización y Validación de Semillas Base32
En `totp::parse_otpauth_uri` (`totp.rs:16-72`):
* Extrae el parámetro `secret=` de URIs `otpauth://totp/...`.
* Procesa cadenas Base32 en bruto eliminando espacios y guiones, y convirtiendo a mayúsculas.
* Valida de forma estricta el alfabeto Base32 de la RFC 4648 (`A-Z` y `2-7`), rechazando caracteres no permitidos (`totp.rs:50-64`).

### 6.3 Limitación Conocida en el Análisis de URIs `otpauth://`
La función `parse_otpauth_uri` extrae **únicamente el parámetro `secret=`**, ignorando silenciosamente los parámetros `algorithm`, `digits` y `period` si estuvieran presentes en la URI. El generador ejecuta rígidamente HMAC-SHA1, 6 dígitos y periodo de 30 segundos. Para servicios minoritarios que exijan SHA256 o códigos de 8 dígitos, los códigos generados no serán válidos.

### 6.4 Custodia de las Semillas TOTP
La semilla secreta Base32 se almacena cifrada en la base de datos local y **jamás se envía a la extensión del navegador**. Cuando la extensión solicita credenciales, el host nativo en Rust calcula el código de 6 dígitos en memoria y transfiere únicamente el código temporal resultante (`src-tauri/src/native_host.rs:180-194` — componente cerrado).

---

## 7. Arquitectura de Licenciamiento Offline (Ed25519)

La validación de licencias de MPLock opera de forma local mediante firmas digitales asimétricas sobre la curva elíptica **Ed25519** (`mplock-core/src/license.rs`).

### 7.1 Formato de la Licencia Criptográfica
La verificación genérica se implementa en `mplock_core::license` (`license.rs:84-167`). La clave de licencia es una cadena Base32 RFC 4648 sin relleno, formateada en 25 bloques de 5 caracteres separados por guiones (125 caracteres legibles).

Al decodificarse (`license.rs:97-105`), la clave produce exactamente **78 bytes binarios**:
```
+------------------------------------------------------------------------+
|                      CLAVE BINARIA (78 BYTES)                          |
+------------------------------------+-----------------------------------+
|     Payload Binario (14 bytes)     |   Firma Ed25519 (64 bytes)        |
+------------------------------------+-----------------------------------+
|  0: Versión de formato (u8 = 1)    |   Firma criptográfica calculada   |
|  1: Código de plan (u8: 1=Pro, 2=T)|   con la clave privada del autor  |
|  2..6: Timestamp de emisión (u32)  |   sobre los primeros 14 bytes     |
|  6..10: Timestamp expiración (u32) |   del payload.                    |
|  10..14: Hash de identidad (4B)    |                                   |
+------------------------------------+-----------------------------------+
```

### 7.2 Verificación Asimétrica
1. Se separa el payload de 14 bytes y la firma de 64 bytes (`license.rs:107-110`).
2. Se instancia la clave pública de verificación Ed25519 (`VerifyingKey`, `license.rs:112-113`).
3. Se invoca `verifying_key.verify(payload_bytes, &signature)` (`license.rs:117-119`).
4. **Verificación de Revocación:** El módulo calcula el hash SHA-256 de los 64 bytes de la firma (`license.rs:122-126`) y comprueba que no figure en la lista de revocación.
5. **Privacidad del Correo:** La dirección de correo electrónico del comprador **no viaja en la clave**; únicamente se incorporan 4 bytes de hash (`email_hash`, `license.rs:156-159`).

### 7.3 Decisión de Diseño Aceptada: Validación Offline y Uso Compartido
Una validación estrictamente offline basada en firmas asimétricas no puede verificar si una misma clave de licencia ha sido ingresada en múltiples máquinas distintas. La aplicación de escritorio mitiga la distribución indiscriminada cifrando la clave en disco con una huella local (`MachineGuid` en el registro de Windows, `src-tauri/src/license.rs`). Si la base de datos se copia a otro equipo, se solicita reingresar la clave para validar la firma. No obstante, MPLock asume el posible uso compartido como una decisión de diseño priorizada en favor de no realizar llamadas de telemetría a servidores remotos.

---

## 8. Comunicación con la Extensión del Navegador y Host Nativo

La integración con Google Chrome, Microsoft Edge y Mozilla Firefox utiliza el protocolo estandarizado de **Mensajería Nativa (Native Messaging)** a través de tuberías estándar `stdin/stdout` (`src-tauri/src/native_host.rs` — componente cerrado).

```
+-----------------------------------+             +------------------------------------+
|       EXTENSIÓN DE NAVEGADOR      |             |         HOST NATIVO (RUST)         |
|   (Chrome / Edge / Firefox MV3)   |             |            mplock.exe              |
|                                   |             |                                    |
|  background.js                    |             |  src-tauri/src/native_host.rs      |
|  connectNative("com.passwords.app")             |  run_native_host(db_path)          |
|                                   |             |                                    |
|  Envía: {"action": "get",         |             |  1. Lee longitud 4B Little-Endian  |
|          "system": "github.com"}  | -- stdin -> |  2. Lee cuerpo JSON                |
|                                   |             |  3. Aplica control de licencia     |
|                                   |             |  4. Busca coincidencia             |
|  Recibe: credencial individual    | <- stdout - |  5. Calcula TOTP efímero en RAM    |
|  (usuario, password, totp_code)   |             |  6. Escribe respuesta en stdout    |
+-----------------------------------+             +------------------------------------+
```

### 8.1 Protocolo de Comunicación
* **Transporte:** Tuberías estándar del sistema operativo (`stdin` / `stdout`).
* **Formato:** Prefijo de 4 bytes Little-Endian con la longitud del mensaje JSON (`native_host.rs:18-29, 128-137`).
* **Límite DoS:** Máximo de mensaje de 1 MB (`length > 1024 * 1024`, `native_host.rs:30-33`).

### 8.2 Lista de Identificadores y Claves de Registro Verificadas
El host nativo se registra exclusivamente en las siguientes claves del Registro de Windows (`HKEY_CURRENT_USER`, verificado en `src-tauri/src/lib.rs:595-608`):
1. **Google Chrome:** `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.passwords.app`
2. **Microsoft Edge:** `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.passwords.app`
3. **Mozilla Firefox:** `HKCU\Software\Mozilla\NativeMessagingHosts\com.passwords.app`

Los manifiestos generados en disco configuran los siguientes identificadores:
* **Chrome y Edge (`allowed_origins`, `src-tauri/src/lib.rs:614-616`):**
  `"chrome-extension://gianaainehpppkelimbojoafaomdpipa/"` (identificador en Chrome Web Store: `gianaainehpppkelimbojoafaomdpipa`).
* **Mozilla Firefox (`allowed_extensions`, `src-tauri/src/lib.rs:597-599`):**
  `"password-manager@example.com"`. *(Nota técnica: Este identificador quedó fijado permanentemente por Mozilla AMO porque fue el ID con el que se subió la extensión por primera vez al catálogo de Mozilla Add-ons; no es un valor temporal ni un requisito exigido técnicamente para enlazar el host nativo, sino la identidad inmutable asignada a la extensión en dicho catálogo).*

### 8.3 Flujo Real de Datos, Exposición de la Contraseña Maestra y Memoria del Navegador
* **Datos transmitidos por el canal:** Consultas de estado (`ping`), bloqueo (`lock`), solicitudes de credenciales por dominio (`get`), y comandos de desbloqueo (`unlock`).
* **Flujo de la Contraseña Maestra en Native Messaging:**
  La contraseña maestra **nunca se transmite por red externa ni a servidores remotos**. Sin embargo, **en el canal local de mensajería nativa, sí viaja en texto plano JSON a través de `stdin`** cuando el usuario solicita desbloquear la base de datos desde la ventana emergente de la extensión:
  1. La extensión envía: `{"action": "unlock", "masterPassword": "<clave>"}`.
  2. La función `run_native_host` (`src-tauri/src/native_host.rs:67-89`) recibe la clave y carga la bóveda en memoria.
  3. **Custodia en memoria:** El subproceso del host nativo retiene la clave maestra en la variable `master_password: Option<Vec<u8>>` durante todo el tiempo que la sesión permanezca desbloqueada, aplicando `zeroize()` al cerrarse o bloquearse (`native_host.rs:77, 92, 123`).
* **Datos retornados:** Únicamente la credencial individual coincidente con el dominio (`system`, `username`, `password`, `notes`) y el código numérico temporal de 6 dígitos del TOTP. La credencial recibida por la extensión reside temporalmente en la memoria JavaScript del navegador gestionada por su recolector de basura, la cual MPLock no puede sobreescribir con ceros desde el proceso de escritorio.
* **Datos que no cruzan el canal:** La base de datos completa no se transmite, la clave DEK no sale del proceso Rust, las semillas secretas Base32 de TOTP nunca se envían al navegador y el código de recuperación no se transmite.

### 8.4 Permisos Declarados en la Extensión (`manifest.json`)
* `nativeMessaging`: Imprescindible para lanzar y comunicarse con el binario local `mplock.exe`.
* `activeTab`: Acceso a la URL y título de la pestaña activa únicamente cuando el usuario pulsa el icono de la extensión.
* `scripting`: Permite insertar las credenciales devueltas exclusivamente en los campos de usuario y contraseña de la pestaña activa tras pulsar "Rellenar". No se solicita el permiso global `<all_urls>`.

### 8.5 Exportación a CSV en Texto Plano (Riesgo Operativo del Cliente)
La función de exportación a CSV genera un archivo en texto plano sin cifrar con todos los secretos del almacén (usuarios, contraseñas y semillas TOTP) para permitir la migración hacia otros gestores. Aunque la aplicación mitiga la fuga accidental exigiendo la reautenticación mediante contraseña maestra y la escritura explícita de la palabra de confirmación `EXPORTAR`, una vez volcado al sistema de archivos el fichero resultante queda expuesto sin protección criptográfica y debe ser eliminado de forma segura por el usuario tras completar la migración.

---

## 9. Delimitación de Código Abierto vs. Lógica Comercial

MPLock mantiene una política de transparencia sobre qué componentes están abiertos a auditoría pública y cuáles pertenecen a la distribución comercial cerrada.

| Componente | Repositorio / Ubicación | Licencia | Estado | Contenido y Verificabilidad |
| :--- | :--- | :--- | :--- | :--- |
| **`mplock-core`** | [github.com/eagoudet/mplock-core](https://github.com/eagoudet/mplock-core) | Dual MIT / Apache-2.0 | **Abierto** | Criptografía (AES-256-GCM, PBKDF2), almacenamiento de bóveda (DEK dual), generación de contraseñas (rejection sampling), motor 2FA/TOTP (RFC 6238), y algoritmo genérico Ed25519. **Auditable públicamente.** |
| **Lógica Comercial de la App** | `src-tauri/src/license.rs` | Propietaria | Cerrado | Límites de cuota (tope de 15 credenciales en Free/Trial), cálculo de días restantes de prueba, verificación de hardware (`MachineGuid`), y claves públicas de producción. **Componente no abierto, no verificable públicamente.** |
| **Host Nativo de la Extensión** | `src-tauri/src/native_host.rs` | Propietaria | Cerrado | Manejo de canal Native Messaging, caché en memoria de sesión desbloqueada y cálculo efímero de TOTP. **Componente no abierto, no verificable públicamente.** |
| **Integración de Pagos** | Configuración Lemon Squeezy | Propietaria | Cerrado | Enlaces de checkout, facturación internacional y webhook de licencias. **Componente no abierto.** |
| **Interfaz y Empaquetado** | `src/`, `src-tauri/` | Propietaria | Cerrado | Código de la interfaz React 19, hooks de instalación NSIS para Windows, y empaquetado de Tauri v2. **Componente no abierto, no verificable públicamente.** |

> **Declaración de Transparencia:** No afirmamos que toda la aplicación de escritorio sea de código abierto. Afirmamos que el núcleo criptográfico (`mplock-core`) que procesa, cifra, deriva y custodia los datos del usuario es independiente, abierto y públicamente auditable.

---

## 10. Pruebas Automatizadas y Reproducibilidad

El espacio de trabajo cuenta con un total de **50 pruebas unitarias automatizadas** verificadas mediante `cargo test`. No obstante, **únicamente las 14 pruebas de `mplock-core` son reproducibles públicamente por la comunidad**, ya que las 36 pruebas restantes corresponden a la aplicación de escritorio cerrada (`tauri_app_lib`).

### 10.1 Inventario de Pruebas Públicamente Reproducibles (`mplock-core`)
Las 14 pruebas unitarias de `mplock-core` se ejecutan en 0,53s (más pruebas estadísticas) y validan:
* `crypto::tests::test_encrypt_decrypt_roundtrip`: Ciclo completo de cifrado y descifrado de texto plano.
* `crypto::tests::test_decrypt_with_wrong_password_fails`: Fallo de autenticación con contraseña incorrecta.
* `crypto::tests::test_decrypt_corrupted_payload_fails`: Rechazo de payloads con bits alterados en ciphertext.
* `crypto::tests::test_decrypt_short_payload_fails`: Rechazo de payloads truncados (< 28 bytes).
* `password::tests::test_generate_secure_password_length_validation`: Validación de longitud mínima (>= 4).
* `password::tests::test_generate_secure_password_guarantees_all_classes`: Comprobación en múltiples longitudes de la inclusión obligatoria de minúsculas, mayúsculas, dígitos y símbolos.
* `storage::tests::test_recovery_code_generation_format`: Validación de formato de 24 caracteres en 6 bloques sin caracteres ambiguos.
* `storage::tests::test_initialize_and_load_db_with_master_and_recovery`: Ciclo completo de inicialización con DEK dual, desbloqueo con contraseña maestra, desbloqueo con código de recuperación y persistencia.
* `totp::tests::test_parse_otpauth_uri`: Normalización de cadenas Base32 y extracción de parámetros.
* `totp::tests::test_rfc6238_test_vectors`: Vectores oficiales del estándar RFC 6238.
* `license::tests::test_base32_decode_valid`, `test_license_creation_and_verification_generic`, `test_revoked_license_fails`, `test_expired_license_fails`: Firma, verificación, expiración y revocación con Ed25519.

### 10.2 Pruebas Internas de la Aplicación de Escritorio (`tauri_app_lib`)
Las 36 pruebas internas de `src-tauri` (no públicas) validan la política de cuotas en Free/Trial, la compatibilidad con almacenes de más de 15 credenciales creados en Pro, la retrocompatibilidad en migraciones, la sanitización del portapapeles, el control de acceso en el host nativo y la suite completa de 9 pruebas de respaldo cifrado (`.mplockbackup`: ciclo roundtrip de cifrado/descifrado, rechazo de contraseña errónea, detección de alteración de bytes, detección de archivos truncados, validación de versiones soportadas y límites de iteraciones, respeto del límite de 15 cuentas en importación, escritura atómica en disco y rechazo de contraseña de exportación idéntica a la maestra).

### 10.3 Cómo Reproducir las Pruebas Abiertas
```bash
# Clonar y verificar el núcleo criptográfico abierto
git clone https://github.com/eagoudet/mplock-core.git
cd mplock-core
cargo test
```

---

## 11. Limitaciones Conocidas y Estado de Auditoría

### 11.1 Ausencia de Auditoría de Terceros
MPLock declara formalmente que **su arquitectura y código fuente NO han sido auditados por una firma de seguridad independiente ni por un auditor externo colegiado** (como Cure53, Trail of Bits o NCC Group). No debe asumirse ninguna certificación externa hasta que dicha evaluación sea contratada y sus resultados publicados.

### 11.2 Binarios, Ausencia de Compilaciones Reproducibles y Firma
* **Código cerrado del instalador:** La aplicación de escritorio es de código cerrado y no dispone de compilaciones reproducibles (*reproducible builds*). Un auditor externo no puede verificar de forma automatizada que el instalador distribuido (`mplock_setup.exe`) provenga de manera exacta del núcleo abierto `mplock-core`.
* **Firma Digital del Instalador:** El instalador actualmente **no cuenta con firma Authenticode EV/OV comercial**, lo que provoca la advertencia preventiva de Microsoft Defender SmartScreen durante la descarga e instalación.
* **Compromiso de Publicación:** Publicar el hash criptográfico SHA-256 del instalador en cada lanzamiento oficial de GitHub Releases para verificación de integridad de descarga.

### 11.3 Canal de Reporte de Vulnerabilidades
Para reportar vulnerabilidades de seguridad, debilidades criptográficas o fallos de implementación, el autor pone a disposición el canal de contacto directo y confidencial:
* **Canal Oficial:** `mplocksoporte@gmail.com`
* **Compromiso de Respuesta:** Máximo 48 horas laborables para acuse de recibo y evaluación técnica inicial.
* **Política de Seguridad:** Documentada formalmente en [`SECURITY.md`](../SECURITY.md).

---

## 12. Historial de Versiones del Documento

| Versión | Fecha | Estado | Versión MPLock | Versión Core | Descripción de Cambios |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **v1.0** | 1 de Octubre de 2026 | Publicación Inicial | v1.3.3 | v0.1.0 (commit `2a5a440`) | Redacción inicial del Whitepaper de Arquitectura Criptográfica. |
| **v1.1** | 2 de Octubre de 2026 | Revisión Técnica Rigurosa | v1.3.3 | v0.1.0 (commit `2a5a440`) | Corrección de flujo de contraseña maestra en Native Messaging, documentación de IDs reales de extensión, aclaración sobre límites del portapapeles, especificación de límites de PBKDF2 frente a Argon2id, advertencia de lectura de memoria en Windows por procesos del mismo usuario, documentación de parámetros ignorados en TOTP, y aclaración de reproducibilidad pública de pruebas. |
| **v1.2** | 2 de Octubre de 2026 | Actualización Técnica Integral | v1.3.3 | v0.1.1 (en `main`) | Actualización de `mplock-core` a `v0.1.1`; habilitación de feature `zeroize` en `aes-gcm = "0.10"` para sobrescritura de subclaves en memoria tras drop; integración de extensiones nativas de Windows en `arboard` (`SetExtWindows::exclude_from_history / exclude_from_cloud`) mitigando persistencia en `Win + V` y nube; temporizador nativo en segundo plano (Tauri/Rust) para vaciado a los 30 s y limpieza al cerrar ventana; delimitación de memoria JavaScript en extensiones; corrección sobre ID inmutable de Firefox fijado por Mozilla AMO (`password-manager@example.com`). |
| **v1.3** | 2 de Octubre de 2026 | Lanzamiento Release v1.4.0 | v1.4.0 | v0.1.1 (en `main`) | Implementación de `Zeroize` en `LAST_COPIED_SECRET` y vaciado en el cierre de ventana y bloqueo; aclaración de límites en apagados abruptos y herramientas de portapapeles de terceros; actualización de pruebas unitarias a 40 (14 núcleo + 26 desktop); sustitución de números de línea por nombres de función en la trazabilidad interna; actualización de versiones de extensiones a v1.10.0 y restricción de instalaciones locales en Chrome. |
| **v1.4** | 3 de Octubre de 2026 | Especificación de Respaldo Cifrado | v1.4.0 | v0.1.1 (en `main`) | Especificación técnica formal del formato de respaldo cifrado `.mplockbackup` (encabezado canónico de 30 bytes, validación de versiones e iteraciones, PBKDF2 600.000 rondas, AES-256-GCM y escritura atómica); inclusión de la exportación a CSV en texto plano en la matriz de riesgos operativos del cliente (sec. 8); ampliación de la suite de pruebas a 50 pruebas unitarias automatizadas (14 en `mplock-core` y 36 en `src-tauri`, con 9 pruebas dedicadas al ciclo de vida de respaldos). |

---

## Anexo: Matriz de Trazabilidad Técnica (Afirmación → Archivo:Línea / Función)

| Concepto Técnico | Parámetro en Código | Archivo en Repositorio | Línea / Función | Estado de Verificabilidad |
| :--- | :--- | :--- | :--- | :--- |
| **PBKDF2 Iteraciones** | `600_000` rondas | `mplock-core/src/crypto.rs` | Línea 13 (`PBKDF2_ITERATIONS`) | **Verificable públicamente** |
| **PBKDF2 Función Hash** | `SimpleHmac<Sha256>` | `mplock-core/src/crypto.rs` | Líneas 6, 10, 21-23 | **Verificable públicamente** |
| **Longitud Salt Criptográfico** | `16` bytes (128 bits) | `mplock-core/src/crypto.rs` | Línea 14 (`SALT_LEN`) | **Verificable públicamente** |
| **Longitud Nonce / IV** | `12` bytes (96 bits) | `mplock-core/src/crypto.rs` | Línea 15 (`IV_LEN`) | **Verificable públicamente** |
| **Algoritmo Simétrico** | `Aes256Gcm` | `mplock-core/src/crypto.rs` | Líneas 1-3, 45, 90 | **Verificable públicamente** |
| **Estructura Payload Base64** | `Salt (16B) + IV (12B) + Ciphertext` | `mplock-core/src/crypto.rs` | Líneas 27-30, 58-64 | **Verificable públicamente** |
| **Zeroize en Clave Derivada** | `key_bytes.zeroize()` | `mplock-core/src/crypto.rs` | Líneas 49, 94 | **Verificable públicamente** |
| **Zeroize en Cifrador AES (Feature)** | `aes-gcm = { version = "0.10", features = ["zeroize"] }` | `mplock-core/Cargo.toml` | Línea 21 | **Verificable públicamente** |
| **Limpieza Portapapeles (30 s)** | `copy_to_clipboard_with_autoclear` | `src-tauri/src/lib.rs` | Función `copy_to_clipboard_with_autoclear` | *Componente no abierto, no verificable públicamente* |
| **Generación de DEK (32B)** | `OsRng.fill_bytes(&mut dek)` | `mplock-core/src/storage.rs` | Líneas 95-96 | **Verificable públicamente** |
| **Envoltura Dual de la DEK** | `encrypted_dek_master` + `recovery` | `mplock-core/src/storage.rs` | Líneas 101-106 | **Verificable públicamente** |
| **Código de Recuperación** | 24 caracteres (32 símbolos Crockford, 120 bits) | `mplock-core/src/storage.rs` | Líneas 70-82 | **Verificable públicamente** |
| **Zeroize en Struct Credential** | `#[zeroize(drop)]` en `struct Credential` | `mplock-core/src/storage.rs` | Líneas 23-24 | **Verificable públicamente** |
| **Rejection Sampling Contraseñas**| `rng.gen_range(0..78)` + loop de clases | `mplock-core/src/password.rs` | Líneas 36-62 | **Verificable públicamente** |
| **Parámetros TOTP** | RFC 6238, SHA1, 6 dígitos, paso 30s | `mplock-core/src/totp.rs` | Líneas 84-96 | **Verificable públicamente** |
| **Normalización Base32 TOTP** | RFC 4648, filtrado de espacios y guiones | `mplock-core/src/totp.rs` | Líneas 39-64 | **Verificable públicamente** |
| **Longitud Licencia Binaria** | `78` bytes (14 payload + 64 firma) | `mplock-core/src/license.rs` | Líneas 6-7, 99-108 | **Verificable públicamente** |
| **Verificación Ed25519** | `verifying_key.verify(payload, &sig)` | `mplock-core/src/license.rs` | Líneas 117-119 | **Verificable públicamente** |
| **Hash SHA-256 Revocación** | Hash de firma contra lista negra | `mplock-core/src/license.rs` | Líneas 121-130 | **Verificable públicamente** |
| **Native Messaging Stdio** | 4-byte LE length + JSON UTF-8 | `src-tauri/src/native_host.rs` | Funciones `run_native_host`, `send_response` | *Componente no abierto, no verificable públicamente* |
| **Límite Mensaje Nativo** | `1024 * 1024` bytes (1 MB) | `src-tauri/src/native_host.rs` | Función `run_native_host` (límite 1 MB) | *Componente no abierto, no verificable públicamente* |
| **Allowed Extensions Firefox** | `["password-manager@example.com"]` | `src-tauri/src/lib.rs` | Función `run` (registro de manifiesto) | *Componente no abierto, no verificable públicamente* |
| **Allowed Origins Chrome/Edge** | `["chrome-extension://gianaainehpppkelimbojoafaomdpipa/"]` | `src-tauri/src/lib.rs` | Función `run` (registro de manifiesto) | *Componente no abierto, no verificable públicamente* |
| **Protección Semilla 2FA** | Solo se devuelve código 6 dígitos | `src-tauri/src/native_host.rs` | Función `handle_get_request` | *Componente no abierto, no verificable públicamente* |
| **Tope 15 Cuentas Free/Trial** | `check_credential_limit` | `src-tauri/src/lib.rs` | Funciones `add_credential`, `add_credentials_bulk` | *Componente no abierto, no verificable públicamente* |
| **Vinculación a Hardware** | `MachineGuid` en Registro Windows | `src-tauri/src/license.rs` | Función `get_device_raw_identifier` | *Componente no abierto, no verificable públicamente* |
| **Encabezado Respaldo Cifrado** | `MPLOCK_BACKUP\0` (30B LE: v1, 600k iter, salt 16B, nonce 12B) | `src-tauri/src/lib.rs` | Funciones `create_encrypted_backup_data`, `parse_and_decrypt_backup_data` | *Componente no abierto, no verificable públicamente* |
| **Escritura Atómica en Disco** | Archivo temporal + `sync_all` + `fs::rename` | `src-tauri/src/lib.rs` | Función `atomic_write_file` | *Componente no abierto, no verificable públicamente* |
| **Exportación CSV Segura** | Reautenticación con contraseña maestra + confirmación "EXPORTAR" | `src-tauri/src/lib.rs`, `src/ExportModal.jsx` | Función `export_vault_csv` y componente `ExportModal` | *Componente no abierto, no verificable públicamente* |
