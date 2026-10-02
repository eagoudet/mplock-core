# Política de Seguridad / Security Policy

## Versiones Soportadas / Supported Versions

Actualmente recibimos y analizamos reportes de seguridad para las siguientes versiones activas:

| Componente | Versión | Estado de Soporte |
| :--- | :--- | :--- |
| `mplock-core` | `0.1.x` | :white_check_mark: Soportado / Supported |
| `MPLock Desktop` | `1.3.x` | :white_check_mark: Soportado / Supported |
| Extensiones (Chrome / Firefox) | `1.7+` / `1.9+` | :white_check_mark: Soportado / Supported |

---

## Reporte de Vulnerabilidades / Reporting a Vulnerability

La seguridad y la integridad criptográfica de MPLock son nuestra máxima prioridad. Si descubres una vulnerabilidad de seguridad o una debilidad criptográfica en `mplock-core` o en la aplicación de escritorio, agradecemos profundamente tu reporte responsable y coordinado.

### Cómo Enviar un Reporte / How to Submit a Report

**Por favor NO abras un Issue público en GitHub para reportar problemas de seguridad no mitigados.**

1. Envía un correo electrónico directo a nuestro canal de seguridad oficial:
   * **Email:** [mplocksoporte@gmail.com](mailto:mplocksoporte@gmail.com)
   * **Asunto sugerido:** `[SECURITY] Reporte de Vulnerabilidad en mplock-core / MPLock`
2. Incluye en tu mensaje toda la información necesaria para comprender y reproducir el hallazgo:
   * Descripción clara del fallo o debilidad identificada.
   * Componente y archivo(s) afectados (ej. `mplock-core/src/crypto.rs`).
   * Pasos reproducibles, código de prueba (*PoC*) o vectores de ataque teóricos.
   * Evaluación de impacto potencial según tu criterio técnico.

### Proceso de Respuesta / Response Process

* **Confirmación de recepción:** Nos comprometemos a acusar recibo de tu reporte en un plazo máximo de **48 horas laborables**.
* **Evaluación y remediación:** Analizaremos el impacto técnico y trabajaremos en un parche o mitigación coordinada.
* **Divulgación coordinada:** Acordaremos contigo un período razonable de divulgación coordinada (habitualmente entre 30 y 90 días) antes de hacer público cualquier detalle, permitiendo que los usuarios de MPLock actualicen sus versiones de forma segura.
* **Reconocimiento:** Con tu consentimiento expreso, te daremos crédito en las notas de la versión correspondiente y en este repositorio por tu contribución a la seguridad del ecosistema.
