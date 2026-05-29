# 📡 Análisis Completo: Top 10 Ataques Bluetooth en Auditorías de Seguridad

**Fecha:** 28 de Mayo, 2026  
**Autor:** Security Director - Bluesky Project  
**Propósito:** Informe técnico para la planificación del proyecto **Bluesky CLI**

---

## Introducción

Bluetooth es una tecnología inalámbrica omnipresente desde 1999, presente en más de 5 mil millones de dispositivos. Opera en la banda ISM de 2.4 GHz con dos variantes principales:

| Variante | Alcance | Casos de uso | Protocolos clave |
|----------|---------|--------------|-----------------|
| **Bluetooth Classic (BR/EDR)** | 10-100m | Audio, teclados, transferencia archivos | L2CAP, RFCOMM, SDP, HID |
| **Bluetooth Low Energy (BLE)** | hasta 400m | IoT, fitness, wearables, salud | GATT, ATT, SMP, L2CAP |

Cada variante presenta una superficie de ataque única. A continuación, los **10 ataques más relevantes** para auditorías de seguridad actualizadas a 2026.

---

## 📋 Top 10 Ataques Bluetooth

### 1️⃣ Bluejacking — El Ataque Clásico de Mensajería

| Dato | Valor |
|------|-------|
| **Tipo** | Spam / Social Engineering |
| **Año** | ~2003 |
| **CVE** | Ninguno |
| **Blanco** | Bluetooth Classic (OBEX Push Profile) |
| **Severidad** | ⚪ Baja |

**Descripción:**  
Envía mensajes no solicitados (vCards/vNotes) a dispositivos cercanos usando el perfil OBEX Push. No hay robo de datos ni control del dispositivo, pero puede usarse para phishing o ingeniería social.

**Cómo funciona:**
1. Atacante escanea dispositivos en modo descubrible
2. Crea una vCard con texto malicioso en el campo "nombre"
3. Envía vía OBEX Push al dispositivo víctima
4. La víctima ve el mensaje en la notificación de recepción

**Mitigación:** Modo no descubrible, no aceptar transferencias no solicitadas.

**Herramientas:** `bluetoothctl`, `obexctl`, `ussp-push`

---

### 2️⃣ Bluesnarfing — Robo de Datos sin Consentimiento

| Dato | Valor |
|------|-------|
| **Tipo** | Data Theft |
| **Año** | 2003 |
| **CVE** | Varios según implementación |
| **Blanco** | Bluetooth Classic (OBEX) |
| **Severidad** | 🟠 Alta |

**Descripción:**  
Explota vulnerabilidades en la implementación de OBEX para acceder a datos del dispositivo víctima: contactos, mensajes, calendario, imágenes, etc. No requiere autenticación en implementaciones vulnerables.

**Cómo funciona:**
1. Atacante establece conexión RFCOMM/OBEX
2. Usa UUIDs de servicio conocidos para acceder a PBAP, MAP, etc.
3. Descarga información sensible sin que el usuario lo note

**Impacto:** Robo de contactos, SMS, fotos, ubicaciones.

**Mitigación:** Mantener firmware actualizado, deshabilitar Bluetooth cuando no se use.

**Herramientas:** `bluesnarfer`, `bluediving`, `Bloover`

---

### 3️⃣ Bluebugging — Control Total del Dispositivo

| Dato | Valor |
|------|-------|
| **Tipo** | Remote Control / RCE |
| **Año** | 2004 |
| **CVE** | Varios según dispositivo |
| **Blanco** | Bluetooth Classic (RFCOMM/SPP) |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Permite al atacante establecer una conexión al perfil de puerto serie (SPP) del dispositivo víctima, obteniendo acceso completo a comandos AT. Esto permite leer/escribir SMS, contactos, hacer llamadas, y más.

**Cómo funciona:**
1. Escanea dispositivos Bluetooth descubribles
2. Establece conexión RFCOMM al canal del Serial Port Profile
3. Envía comandos AT para controlar el dispositivo
4. Puede leer mensajes, contactos, hacer llamadas, navegar por internet

**Impacto:** Compromiso total del dispositivo telefónico.

**Mitigación:** Deshabilitar Bluetooth cuando no se use, mantener firmware actualizado.

**Herramientas:** `bluebugger`, `Bloover`, `hcitool`, `rfcomm`

---

### 4️⃣ BIAS — Bluetooth Impersonation Attacks (CVE-2020-10135)

| Dato | Valor |
|------|-------|
| **Tipo** | Impersonation / MitM |
| **Año** | 2020 |
| **CVE** | CVE-2020-10135 |
| **Blanco** | Bluetooth Classic BR/EDR |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Ataque de especificación que permite a un atacante hacerse pasar por un dispositivo previamente emparejado. BIAS explota fallos en el manejo de la autenticación en el protocolo Bluetooth a nivel de capa de enlace (LMP).

**Cómo funciona:**
1. Atacamento escanea direcciones MAC de dispositivos en busca de parejas
2. Se hace pasar por un dispositivo previamente emparejado
3. Engaña al protocolo de autenticación haciéndole creer que no requiere comprobación
4. Establece una conexión cifrada sin tener la clave de enlace
5. Puede interceptar todo el tráfico (MitM) o simplemente suplantar

**Impacto:** Suplantación de cualquier dispositivo Bluetooth Classic. Afecta a todos los dispositivos que siguen el estándar Bluetooth (4.0 a 5.2).

**Mitigación:** Bluetooth 5.3+ corrige el diseño. Parches de firmware específicos.

**Herramientas:** `blue-tap`, `BlueToolkit`, `bluesploit`, Ubertooth One

---

### 5️⃣ KNOB — Key Negotiation of Bluetooth (CVE-2019-9506)

| Dato | Valor |
|------|-------|
| **Tipo** | Downgrade / Cryptographic Attack |
| **Año** | 2019 |
| **CVE** | CVE-2019-9506 |
| **Blanco** | Bluetooth Classic BR/EDR y BLE |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Ataque de negociación de claves que permite a un atacante reducir la entropía de la clave de sesión a solo **1 byte** (8 bits). Con una clave de 1 byte, la fuerza bruta toma milisegundos, permitiendo descifrar todo el tráfico.

**Cómo funciona:**
1. Atacante se sitúa como MitM durante el emparejamiento
2. Intercepta el intercambio `LMP_encryption_key_size_req`
3. Modifica el tamaño de clave solicitado a 1 byte (mínimo)
4. Ambos dispositivos aceptan porque el estándar lo permite
5. Atacante fuerza bruta la clave de 1 byte en milisegundos
6. Descifra todo el tráfico cifrado

**Impacto:** Descifrado completo de comunicaciones Bluetooth. Afecta a Bluetooth 4.0 hasta 5.1.

**Mitigación:** Bluetooth 5.1+ requiere mínimo 7 bytes. Rechazar conexiones con entropía < 56 bits.

**Herramientas:** `blue-tap` (con DarkFirmware), `bluesploit`, KNOB PoC

---

### 6️⃣ BLUFFS — Bluetooth Forward and Future Secrecy (CVE-2023-24023)

| Dato | Valor |
|------|-------|
| **Tipo** | Session Key Derivation Attack |
| **Año** | 2023 |
| **CVE** | CVE-2023-24023 |
| **Blanco** | Bluetooth Classic BR/EDR y BLE |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
BLUFFS rompe la seguridad forward y future de Bluetooth. Permite derivar, reutilizar o forzar claves de sesión débiles, comprometiendo no solo la sesión actual sino también sesiones pasadas y futuras.

**Cómo funciona:**
1. Explota la derivación de clave de sesión basada en números aleatorios que pueden ser forzados
2. Atacante puede hacer que dos sesiones diferentes compartan la misma clave de sesión
3. Descifra tráfico de sesiones pasadas (rompe forward secrecy)
4. Predice claves de sesiones futuras (rompe future secrecy)

**Impacto:** Compromiso total de confidencialidad a largo plazo. No necesita estar presente durante el emparejamiento original.

**Mitigación:** Implementaciones que usan ECDH con aleatoriedad fuerte. Parches de firmware.

**Herramientas:** `bluesploit`, `blue-tap` (con DarkFirmware), BLUFFS PoC

---

### 7️⃣ BlueBorne — RCE por Bluetooth (CVE-2017-1000251, etc.)

| Dato | Valor |
|------|-------|
| **Tipo** | RCE / Information Leak |
| **Año** | 2017 |
| **CVE** | CVE-2017-1000251, CVE-2017-0781, CVE-2017-0785 |
| **Blanco** | Android, iOS, Windows, Linux (BlueZ) |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Conjunto de 8 vulnerabilidades que permiten ejecución remota de código sin interacción del usuario, sin necesidad de emparejamiento, y con el Bluetooth encendido. Afecta a prácticamente todas las plataformas.

**Cómo funciona:**
1. Atacante escanea dispositivos con Bluetooth activo
2. Envía paquetes L2CAP malformados
3. Explota buffer overflows en la pila Bluetooth (BlueZ, Android, iOS)
4. Obtiene ejecución remota de código en el kernel o sistema
5. Puede instalar malware, robar datos, espiar

**Impacto:** RCE masivo en millones de dispositivos. No requiere autenticación ni emparejamiento.

**Mitigación:** Parches de seguridad publicados en 2017-2018. Dispositivos sin actualizar siguen siendo vulnerables.

**Herramientas:** `blueborne-scanner`, `metasploit` (auxiliary/bluetooth/blueborne), `bluesploit`

---

### 8️⃣ BLESA — BLE Spoofing Attack (CVE-2020-9770)

| Dato | Valor |
|------|-------|
| **Tipo** | Spoofing / MitM |
| **Año** | 2020 |
| **CVE** | CVE-2020-9770 (iOS), CVE-2020-10556 (Android) |
| **Blanco** | Bluetooth Low Energy (BLE) |
| **Severidad** | 🟠 Alta |

**Descripción:**  
Ataque de suplantación en BLE durante el reconnection process. Cuando un dispositivo central se reconecta a un periférico BLE previamente emparejado, BLESA permite que un atacante suplante al periférico sin tener la clave de largo plazo (LTK).

**Cómo funciona:**
1. Víctima tiene un dispositivo BLE emparejado (ej. pulsera fitness)
2. Atacante crea un dispositivo BLE falso con el mismo nombre y MAC
3. Durante la reconexión, el atacante omite la reautenticación
4. El dispositivo central acepta la conexión sin verificar la LTK
5. Atacante puede enviar datos falsos o interceptar información

**Impacto:** Suplantación de dispositivos IoT, smart locks, wearables.

**Mitigación:** Forzar reautenticación en reconexión. Parches iOS 13.4.1+.

**Herramientas:** BLE spoofing tools, `gatttool`, `btlejack`, nRF52840

---

### 9️⃣ SweynTooth — BLE Link Layer Vulnerabilities (CVE-2019-16336+)

| Dato | Valor |
|------|-------|
| **Tipo** | RCE / DoS / Crash |
| **Año** | 2020 |
| **CVE** | CVE-2019-16336, CVE-2019-17060, CVE-2019-17061, etc. |
| **Blanco** | BLE SoCs (Texas Instruments, NXP, Cypress, Dialog, etc.) |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Conjunto de 12 vulnerabilidades en los SoCs BLE más populares del mercado. Explotan fallos en la capa de enlace (Link Layer) de BLE, permitiendo desde Denial of Service hasta Ejecución Remota de Código.

**Cómo funciona:**
1. Atacante envía paquetes BLE malformados a nivel de Link Layer
2. Explota fallos en: manejo de LLID, overflow de ATT, bypass de autenticación
3. Provoca: kernel panic, RCE, bypass de seguridad, o lectura de memoria

**Impacto:** Dispositivos médicos, IoT, smart home. Algunos exploits permiten desbloquear cerraduras inteligentes.

**Mitigación:** Parches de firmware de fabricantes (post-2020). Verificar versión de SDK del SoC.

**Herramientas:** SweynTooth PoC, `bluesploit`, `BlueToolkit`, nRF52840

---

### 🔟 WhisperPair — Google Fast Pair Hijacking (CVE-2025-36911)

| Dato | Valor |
|------|-------|
| **Tipo** | Connection Hijacking / Tracking |
| **Año** | 2026 |
| **CVE** | CVE-2025-36911 |
| **Blanco** | Google Fast Pair (Android) |
| **Severidad** | 🔴 Crítica |

**Descripción:**  
Vulnerabilidad descubierta en 2026 que permite secuestrar accesorios Bluetooth que usan Google Fast Pair. Afecta a auriculares de Sony, JBL, Jabra, Marshall, Xiaomi, Nothing, OnePlus, Soundcore, Logitech y Google. Permite escucha del micrófono y rastreo de ubicación.

**Cómo funciona:**
1. Atacante se coloca cerca del accesorio durante el modo de emparejamiento
2. Explota fallos en el intercambio de claves de Fast Pair
3. Secuestra la conexión antes de que el legítimo propietario se conecte
4. Si el atacante es el primero en emparejarse, su cuenta queda como propietaria
5. Puede escuchar el micrófono del accesorio y rastrear su ubicación vía Find Hub

**Impacto:** Secuestro de accesorios de audio, espionaje, rastreo de ubicación. 68% de dispositivos probados vulnerables.

**Mitigación:** Actualizaciones de firmware de cada fabricante. No solucionable solo actualizando el móvil.

**Herramientas:** WhisperPair PoC, herramientas específicas de investigación académica

---

## 📊 Matriz Comparativa

| # | Ataque | Tipo | CVE | Año | Severidad | Classic | BLE | ¿Requiere Pairing? |
|---|--------|------|-----|-----|-----------|---------|-----|-------------------|
| 1 | Bluejacking | Social Eng | — | 2003 | ⚪ Baja | ✅ | ❌ | No |
| 2 | Bluesnarfing | Data Theft | — | 2003 | 🟠 Alta | ✅ | ❌ | No |
| 3 | Bluebugging | RCE | — | 2004 | 🔴 Crítica | ✅ | ❌ | No |
| 4 | BIAS | Impersonation | CVE-2020-10135 | 2020 | 🔴 Crítica | ✅ | ❌ | Sí (previo) |
| 5 | KNOB | Crypto Downgrade | CVE-2019-9506 | 2019 | 🔴 Crítica | ✅ | ✅ | Sí (durante) |
| 6 | BLUFFS | Session Key | CVE-2023-24023 | 2023 | 🔴 Crítica | ✅ | ✅ | No |
| 7 | BlueBorne | RCE | CVE-2017-1000251 | 2017 | 🔴 Crítica | ✅ | ❌ | No |
| 8 | BLESA | Spoofing | CVE-2020-9770 | 2020 | 🟠 Alta | ❌ | ✅ | Sí (previo) |
| 9 | SweynTooth | RCE/DoS | CVE-2019-16336+ | 2020 | 🔴 Crítica | ❌ | ✅ | No |
| 10 | WhisperPair | Hijacking | CVE-2025-36911 | 2026 | 🔴 Crítica | ❌ | ✅ | No |

---

## 🛠️ Herramientas de Auditoría Bluetooth Existentes

| Herramienta | Tipo | Cobertura | Hardware Requerido |
|------------|------|-----------|-------------------|
| **Blue-Tap** | Pentest Toolkit | Classic + BLE + Automotriz | RTL8761B (TP-Link UB500) |
| **BlueToolkit** | Testing Framework | Classic (43 exploits) | Adaptador Bluetooth estándar |
| **BlueSploit** | Framework (Metasploit-style) | Classic + BLE (55 módulos) | Ubertooth One, nRF52840 |
| **BluSnu** | Mobile-first (Android) | Classic + BLE | Nativo Android |
| **Cerberus Blue** | Pentesting Tool | Classic + BLE + ADB | Adaptador Bluetooth estándar |
| **PerfektBlue** | Framework Automotriz | Classic + CAN | Adaptador Bluetooth + CAN |
| **Blueborne-scanner** | Scanner | BlueBorne detection | Adaptador Bluetooth |
| **Bettercap BLE** | Framework | BLE (con módulo) | Adaptador BLE |

---

## 🔧 Stack Tecnológico Recomendado para Bluesky

```
bluesky/
├── Core (Python 3.10+)
│   ├── Gestión de comandos CLI (click/argparse)
│   ├── Módulo de hardware detection
│   ├── Gestor de sesiones/resultados
│   └── Interfaz de reportes
│
├── Módulos de Ataque (10 ataques principales)
│   ├── bluejacking.py  → OBEX Push, vCard spoofing
│   ├── bluesnarfing.py → OBEX data extraction (PBAP, MAP)
│   ├── bluebugging.py  → RFCOMM/AT command injection
│   ├── bias.py         → BIAS impersonation (CVE-2020-10135)
│   ├── knob.py         → KNOB key downgrade (CVE-2019-9506)
│   ├── bluffs.py       → BLUFFS session key (CVE-2023-24023)
│   ├── blueborne.py    → BlueBorne RCE/scan (CVE-2017-...)
│   ├── blesa.py        → BLE spoofing recon (CVE-2020-9770)
│   ├── sweyntooth.py   → SweynTooth scanner (CVE-2019-...)
│   └── whisperpair.py  → Fast Pair checker (CVE-2025-36911)
│
├── Módulos de Escaneo
│   ├── device_scanner.py  → Descubrimiento de dispositivos
│   ├── service_scanner.py → SDP service enumeration
│   ├── vuln_scanner.py    → Detección de vulnerabilidades
│   └── ble_scanner.py     → BLE advertisement scanning
│
├── Módulos de Explotación
│   ├── keystroke_inject.py → HID keyboard injection
│   ├── l2cap_fuzz.py       → L2CAP fuzzing
│   └── rfcomm_exploit.py   → RFCOMM reverse shell
│
├── Utilerías
│   ├── mac_spoofer.py   → BD_ADDR spoofing
│   ├── packet_capture.py → hcidump/btmon wrapper
│   └── termux_hardware.py → Soporte específico Termux
│
├── Informes
│   ├── report_html.py
│   └── report_json.py
│
├── Scripts de instalación
│   ├── install_termux.sh
│   └── install_linux.sh
│
└── Tests
    └── test_*.py
```

---

## 📌 Conclusiones y Plan de Acción

### Observaciones Clave:
1. **Bluetooth sigue siendo un vector de ataque crítico** en 2026 con vulnerabilidades nuevas como WhisperPair
2. **La fragmentación es el principal problema** — cada ataque requiere herramientas diferentes
3. **Existe un nicho claro** para una herramienta unificada tipo "Metasploit para Bluetooth" funcional en **Termux y Linux**
4. **Hardware mínimo viable**: Adaptador CSR 4.0 (~$5) para ataques Classic; nRF52840 (~$30) para BLE avanzado

### Propuesta Bluesky:
Bluesky será una **CLI unificada de auditoría Bluetooth** que:
- ✅ Funcione en **Termux (Android)** y **Linux**
- ✅ Implemente los **10 ataques principales** como módulos independientes
- ✅ Genere **reportes profesionales** en HTML/JSON
- ✅ Tenga un **sistema modular** tipo Metasploit
- ✅ Sea **extensible** para agregar nuevos ataques/CVEs
- ✅ Incluya **modo educativo** que explique cada ataque paso a paso

---

*Documento generado como parte del análisis inicial del proyecto **Bluesky** — Sistema de Auditoría Bluetooth*
