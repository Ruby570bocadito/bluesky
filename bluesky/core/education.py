#!/usr/bin/env python3
"""
bluesky Educational Mode
========================
Modo educativo: explica cada módulo de bluesky paso a paso — qué es el
ataque, cómo funciona a nivel de protocolo, su impacto y, sobre todo,
cómo MITIGARLO.

Propósito: formación en seguridad Bluetooth. Todo el contenido es
conocimiento público (papers de investigación, avisos CVE, documentación
del Bluetooth SIG) y está orientado al defensor: cada entrada termina en
mitigaciones accionables.

Uso:
    bluesky educate <módulo>      → Explicación de un módulo
    bluesky educate               → Índice de módulos disponibles
    educate <módulo>              (desde la consola REPL)
"""

from __future__ import annotations

from typing import Dict, List, Optional

# ─── Base de conocimiento educativa ─────────────────────────────────────────
# Cada entrada: what (qué es), how (fases, conceptual), impact, mitigation
# (defensas accionables), references (fuentes públicas).

EDU_DB: Dict[str, Dict] = {
    "knob": {
        "title": "KNOB — Key Negotiation Of Bluetooth (CVE-2019-9506)",
        "what": (
            "KNOB explota una debilidad del proceso de emparejamiento "
            "BR/EDR: la negociación de la entropía de la clave de enlace no "
            "se autentica. Un atacante en el rango de radio puede manipular "
            "los mensajes LMP para forzar que la clave de sesión se negocie "
            "con 1 byte (8 bits) de entropía en lugar de los 16 bytes "
            "estándar."
        ),
        "how": [
            "1. El atacante se sitúa en el rango de radio durante el pairing "
            "de dos dispositivos víctima.",
            "2. Intercepta y modifica los mensajes LMP_comb_key / entropy "
            "de la negociación, declarando soportar solo 1 byte de entropía.",
            "3. Ambos dispositivos aceptan el valor degradado (el campo no "
            "está autenticado por el estándar).",
            "4. Con una clave de 8 bits, el atacante fuerza bruta la clave "
            "de sesión en milisegundos y descifra todo el tráfico posterior.",
        ],
        "impact": (
            "Descifrado completo del tráfico Bluetooth Classic (audífonos, "
            "teclados, transferencias) sin conocer ningún secreto previo. "
            "Afecta a los modos Secure Simple Pairing y Secure Connections "
            "de chips no parcheados (2019 o anterior)."
        ),
        "mitigation": [
            "Actualizar el firmware del controlador Bluetooth: los chips "
            "parcheados rechazan entropías menores a 16 bytes.",
            "Asegurarse de que el stack BlueZ/Windows/Android esté al día "
            "(los parches de 2019 en adelante validan la entropía mínima).",
            "Para auditoría: verificar que el dispositivo negocie "
            "Secure Connections y entropía máxima tras el parche.",
            "En entornos sensibles, considerar desactivar Bluetooth BR/EDR "
            "si solo se usa BLE.",
        ],
        "references": [
            "https://knobattack.com/",
            "CVE-2019-9506",
        ],
    },
    "bias": {
        "title": "BIAS — Bluetooth Impersonation Attack (CVE-2020-10135)",
        "what": (
            "BIAS permite suplantar a un dispositivo ya emparejado en una "
            "conexión Bluetooth Classic, sin conocer la clave de enlace. "
            "Explota la ausencia de autenticación mutua obligatoria en el "
            "establecimiento de la conexión baseband."
        ),
        "how": [
            "1. El atacante descubre la dirección MAC de un dispositivo "
            "emparejado previamente con la víctima (p.ej. por sniffing o "
            "un escaneo previo).",
            "2. Suplanta esa MAC y solicita una conexión como esclavo o "
            "maestro, evitando la autenticación (rol que no la exige).",
            "3. Si la víctima exige autenticación, el atacante baja a "
            "legacy pairing o manipula el tipo de clave soportada.",
            "4. Una vez conectado, puede leer/escribir datos como si fuera "
            "el dispositivo legítimo, y en combinación con KNOB descifrar "
            "tráfico cifrado.",
        ],
        "impact": (
            "Suplantación de identidad de cualquier dispositivo ya "
            "emparejado: acceso a perfiles de audio, telefonía o "
            "transferencia de archivos sin alertas al usuario."
        ),
        "mitigation": [
            "Aplicar los parches de Bluetooth SIG publicados en 2020 "
            "(autenticación mutua obligatoria).",
            "Eliminar emparejamientos no utilizados de la lista de "
            "dispositivos de confianza.",
            "Configurar los dispositivos en modo no descubrible cuando no "
            "se necesiten emparejamientos nuevos.",
            "Para auditoría: verificar que el objetivo rechace conexiones "
            "sin autenticación mutua tras el parche.",
        ],
        "references": [
            "https://bias.bluetooth.org/",
            "CVE-2020-10135",
        ],
    },
    "bluffs": {
        "title": "BLUFFS — Bluetooth Forward and Future Secrecy (CVE-2023-24027)",
        "what": (
            "BLUFFS explota debilidades en la derivación de la clave de "
            "sesión de Bluetooth Classic para romper la confidencialidad de "
            "sesiones pasadas y futuras: permite derivar o reutilizar claves "
            "de sesión antiguas aunque el emparejamiento fuera seguro."
        ),
        "how": [
            "1. El atacante obtiene una muestra del tráfico cifrado entre "
            "las víctimas (p.ej. con un sniffer de radio).",
            "2. Durante una nueva conexión, fuerza parámetros de sesión "
            "(valores de BLK/encriptación) que hacen que la clave de sesión "
            "sea derivable a partir de datos públicos.",
            "3. Con la clave derivada, descifra la sesión actual y puede "
            "reusar el material para sesiones futuras con la misma pareja "
            "de dispositivos.",
        ],
        "impact": (
            "Compromiso de confidencialidad presente, pasada y futura entre "
            "dispositivos afectados (6 de las 19 unidades analizadas en el "
            "paper original eran explotables en los dos sentidos)."
        ),
        "mitigation": [
            "Parchear el stack (Linux BlueZ y firmware de chip con los "
            "fixes de 2023 que validan los parámetros de derivación).",
            "Re-emparejar los dispositivos tras aplicar parches para "
            "regenerar el material de claves.",
            "Evitar reutilizar emparejamientos antiguos entre dispositivos "
            "no confiables.",
        ],
        "references": [
            "https://github.com/francozappa/bluffs",
            "CVE-2023-24027",
        ],
    },
    "blueborne": {
        "title": "BlueBorne — RCE sobre la pila Bluetooth (CVE-2017-0781 y familia)",
        "what": (
            "BlueBorne es una familia de vulnerabilidades (2017) en pilas "
            "Bluetooth de Android, Linux, iOS y Windows que permite "
            "ejecución remota de código o fuga de información SIN "
            "emparejamiento previo y sin interacción del usuario."
        ),
        "how": [
            "1. El atacante escanca dispositivos con Bluetooth activo "
            "(inquiry) e identifica la pila objetivo por fingerprinting.",
            "2. Envía paquetes L2CAP malformados que explotan un desbordamiento "
            "de memoria en el procesamiento de la pila (p.ej. "
            "CVE-2017-0781 en Android BNEC/PAN).",
            "3. Con éxito, obtiene ejecución de código con privilegios del "
            "servicio Bluetooth, sin que el dispositivo esté emparejado ni "
            "en modo visible.",
        ],
        "impact": (
            "Compromiso total del dispositivo (RCE) propagable estilo "
            "gusano. Crítico en flotas de dispositivos IoT/Android sin "
            "parchear de 2017."
        ),
        "mitigation": [
            "Aplicar parches de seguridad de 2017 en adelante (todos los "
            "sistemas modernos ya lo están).",
            "Desactivar Bluetooth cuando no se use en dispositivos críticos "
            "o sin soporte.",
            "Segmentar dispositivos IoT Bluetooth en redes/canales aislados.",
            "Para auditoría: este check verifica el fingerprint de pila y "
            "los servicios expuestos, no ejecuta el exploit real.",
        ],
        "references": [
            "https://www.armis.com/blueborne/",
            "CVE-2017-0781, CVE-2017-0782, CVE-2017-0783, CVE-2017-0785",
        ],
    },
    "bluefrag": {
        "title": "BlueFrag — RCE sobre Android vía L2CAP (CVE-2020-0022)",
        "what": (
            "BlueFrag es un desbordamiento de búfer en el componente "
            "Bluetooth de Android 8-9 explotable enviando un paquete L2CAP "
            "malformado a un dispositivo Android. En Android 8 puede dar "
            "RCE silencioso; en Android 9 provoca fuga de memoria y crash."
        ),
        "how": [
            "1. El atacante conoce la MAC de la víctima (un dispositivo "
            "Android 8/9 con Bluetooth activo).",
            "2. Establece un canal L2CAP hacia el perfil HCI/BNEP de la "
            "víctima y envía fragmentos de paquete malformados.",
            "3. En Android 8 (con emparejamiento previo) la corrupción de "
            "memoria permite ejecución de código; en Android 9 provoca "
            "fuga de memoria del heap.",
        ],
        "impact": (
            "RCE en Android 8 sin interacción del usuario (con MAC "
            "conocida), denegación de servicio y fuga de memoria en "
            "Android 9. Parcheado desde el boletín de febrero de 2020."
        ),
        "mitigation": [
            "Actualizar Android al boletín de seguridad de 2020-02 o "
            "posterior.",
            "Usar direcciones MAC privadas/aleatorias cuando sea posible.",
            "Desactivar la visibilidad Bluetooth por defecto.",
        ],
        "references": [
            "https://insight-jsec.blogspot.com/2020/02/bluefrag-and-vulnerabilities-in.html",
            "CVE-2020-0022",
        ],
    },
    "blesa": {
        "title": "BLESA — BLE Spoofing Attack (re-conexión insegura)",
        "what": (
            "BLESA explota la re-conexión de dispositivos BLE: cuando un "
            "dispositivo se reconecta a un peer previamente emparejado, "
            "algunas implementaciones NO autentican al peer (ignoran las "
            "verificaciones de la especificación), permitiendo que un "
            "atacante suplante al dispositivo legítimo."
        ),
        "how": [
            "1. El atacante fuerza la desconexión del vínculo legítimo "
            "(p.ej. con un mensaje de terminación de enlace BLE).",
            "2. Suplanta la identidad del peer legítimo (MAC + identidad "
            "del enlace BLE) durante la re-conexión.",
            "3. Si el dispositivo víctima no exige autenticación en la "
            "re-conexión, el atacante accede a los atributos GATT como si "
            "fuera el dispositivo legítimo.",
        ],
        "impact": (
            "Acceso a características GATT protegidas (lectura/escritura) "
            "en wearables, cerraduras inteligentes y dispositivos IoT. "
            "Depende de la implementación de la pila BLE del fabricante."
        ),
        "mitigation": [
            "Parchear las pilas BLE afectadas (el paper documenta iOS y "
            "bibliotecas Linux populares).",
            "En diseño de producto: exigir autenticación y cifrado en cada "
            "re-conexión ( bonding con authenticated pairing).",
            "Verificar con este módulo si un dispositivo exige autenticación "
            "en re-conexión antes de exponer características sensibles.",
        ],
        "references": [
            "https://wustl.edu/about/news-sources/news/blesa-bluetooth-vulnerability/",
            "USENIX Security 2020 — BLESA",
        ],
    },
    "bluejacking": {
        "title": "Bluejacking — mensajes no solicitados vía OBEX Push",
        "what": (
            "Bluejacking envía tarjetas de contacto (vCard) o mensajes no "
            "solicitados a dispositivos Bluetooth cercanos en modo "
            "descubrible usando el perfil OBEX Object Push. No roba datos "
            "ni controla el dispositivo: es un vector de ingeniería social "
            "(la notificación del mensaje puede parecer legítima)."
        ),
        "how": [
            "1. Escaneo de dispositivos descubribles (inquiry).",
            "2. Se construye una vCard con el texto del mensaje en el campo "
            "de nombre.",
            "3. Se envía vía OBEX Push (RFCOMM canal 9 por defecto) al "
            "objetivo.",
            "4. La víctima ve una notificación de contacto entrante con el "
            "mensaje — si la acepta, el mensaje queda en sus contactos.",
        ],
        "impact": (
            "Bajo: molestia/phishing de proximidad. Puede usarse como "
            "reconnaissance (confirma qué dispositivos aceptan OBEX) o "
            "como puerta a ataques de ingeniería social más elaborados."
        ),
        "mitigation": [
            "Mantener el dispositivo en modo no descubrible fuera del "
            "emparejamiento.",
            "Rechazar transferencias de contactos/archivos no solicitadas.",
            "Desactivar el perfil OBEX Object Push si no se usa.",
        ],
        "references": [
            "Historia: término acuñado en 2003 (primer 'jack' documentado).",
        ],
    },
    "bluesnarfing": {
        "title": "Bluesnarfing — extracción de datos vía OBEX sin consentimiento",
        "what": (
            "Bluesnarfing explota implementaciones OBEX mal configuradas "
            "para LEER objetos (agenda, contactos, correos, archivos) de un "
            "dispositivo sin emparejamiento ni consentimiento, aprovechando "
            "canales OBEX que aceptan conexiones de confianza sin "
            "autenticación."
        ),
        "how": [
            "1. Escaneo y enumeración de servicios SDP del objetivo.",
            "2. Identificación de canales RFCOMM con perfiles OBEX "
            "(Object Push, FTP, IrMC Sync).",
            "3. Conexión directa a los canales con peticiones OBEX GET "
            "sin pasar por el flujo de emparejamiento.",
            "4. Si el dispositivo confía en conexiones del canal (bug de "
            "implementación), responde con los objetos solicitados.",
        ],
        "impact": (
            "Robo de datos personales: contactos, calendario, imágenes, "
            "mensajes. Afectó especialmente a teléfonos de los 2000s; los "
            "dispositivos modernos exigen autenticación, pero IOT y "
            "hardware embebido legacy siguen siendo vulnerables."
        ),
        "mitigation": [
            "Actualización de firmware; desactivar OBEX FTP/irMC si no se "
            "usa.",
            "Modo no descubrible por defecto.",
            "Auditar con este módulo qué canales OBEX responden sin "
            "autenticación y cerrarlos en la configuración del dispositivo.",
        ],
        "references": [
            "Adam Laurie — A/L 'Bluesnarfing' (2003-2004)",
        ],
    },
    "bluebugging": {
        "title": "Bluebugging — control AT del dispositivo vía RFCOMM",
        "what": (
            "Bluebugging explota canales RFCOMM que aceptan conexiones sin "
            "autenticación para hablar directamente con el módem del "
            "dispositivo mediante comandos AT: realizar llamadas, leer "
            "SMS, redirigir audio o usar el dispositivo como gateway."
        ),
        "how": [
            "1. Enumeración SDP para localizar el canal RFCOMM del perfil "
            "de manos libres/dial-up mal protegido.",
            "2. Conexión RFCOMM directa al canal vulnerable.",
            "3. Envío de comandos AT (ATA, ATD, AT+CMGR...) que el módem "
            "ejecuta sin verificar origen.",
            "4. El atacante controla llamadas/SMS del dispositivo a "
            "distancia de radio.",
        ],
        "impact": (
            "Escucha de llamadas, envío de SMS de pago, uso del micrófono "
            "en implementaciones afectadas. Requiere canales sin "
            "autenticación (hoy raros en móviles, presentes en hardware "
            "embebido)."
        ),
        "mitigation": [
            "Firmware actualizado; exigir emparejamiento autenticado para "
            "todos los perfiles con comandos AT.",
            "Desactivar los perfiles Bluetooth de voz/dial-up no usados.",
            "Monitorear conexiones RFCOMM entrantes inesperadas en "
            "dispositivos embebidos.",
        ],
        "references": [
            "Johannes B. 'Bluebugging' (2004)",
        ],
    },
    "sweyntooth": {
        "title": "SweynTooth — suite de crashes BLE (12 CVEs, 2019-2020)",
        "what": (
            "SweynTooth agrupa 12 vulnerabilidades en SoCs BLE (Telink, "
            "Nordic, ST, Cypress, Dialog...) que provocan denegación de "
            "servicio, deadlocks o bypass de LL (Link Layer) con paquetes "
            "malformados en la negociación de conexión/longitud de datos."
        ),
        "how": [
            "1. Escaneo BLE para identificar el SoC del objetivo "
            "(fingerprint por nombre/UUIDs de fabricante).",
            "2. Selección del CVE aplicable al chip detectado (p.ej. "
            "truncado de LL_DATA_LENGTH_UPDATE, overflow de "
            "LL_CONNECTION_PARAM_REQ).",
            "3. Envío del paquete Link Layer malformado durante el "
            "handshake de conexión.",
            "4. El dispositivo objetivo crashea, se reinicia o entra en "
            "deadlock hasta un reset manual.",
        ],
        "impact": (
            "DoS persistente de dispositivos BLE (dispositivos médicos y "
            "industriales son los casos de uso citados en el advisory de "
            "CISA). No extrae datos: interrumpe el servicio."
        ),
        "mitigation": [
            "Actualizar el SDK/firmware del SoC BLE a versiones con los "
            "fixes (2020 en adelante).",
            "Para operadores: inventariar dispositivos BLE por chip y "
            "verificar con este módulo qué unidades crashean.",
            "Segregar físicamente los dispositivos BLE críticos de radio "
            "hostil.",
        ],
        "references": [
            "https://github.com/matthias-baatz/SweynTooth",
            "CISA ICS Advisory 2020",
        ],
    },
    "whisperpair": {
        "title": "WhisperPair — bypass de pairing en algunos auriculares BLE",
        "what": (
            "WhisperPair (2024) describe cómo ciertos auriculares/dispositivos "
            "BLE aceptan conexiones de escritura GATT sin completar el "
            "pairing bond, o aceptan pairing con parámetros degradados, "
            "permitiendo a un atacante enviar comandos de control "
            "(reproducción, asistente de voz) sin pertenecer al vínculo."
        ),
        "how": [
            "1. Escaneo BLE del objetivo y lectura de sus características "
            "GATT expuestas.",
            "2. Detección de características de escritura accesibles sin "
            "cifrado o con pairing just-works degradado.",
            "3. Escritura de comandos de control (HID/audio) directamente "
            "sobre esas características.",
        ],
        "impact": (
            "Control no autorizado de periféricos (audio, asistentes) y en "
            "algunos casos lectura de metadatos. Impacto limitado a los "
            "perfiles expuestos."
        ),
        "mitigation": [
            "Actualizar firmware del periférico si el fabricante publicó "
            "parche.",
            "En diseño de producto: exigir cifrado con autenticación "
            "(authenticated pairing) para TODAS las características de "
            "escritura.",
            "Desemparejar dispositivos no reconocidos de la lista del "
            "teléfono.",
        ],
        "references": [
            "WhisperPair — Comsec / investigación 2024",
        ],
    },
    "crackle": {
        "title": "Crackle — crackeo de TK/LTK en emparejamientos BLE legacy",
        "what": (
            "Crackle analiza capturas de tráfico BLE y craquea el "
            "Temporary Key (TK) de emparejamientos Legacy Pairing cuando "
            "usan Just Works (TK=0) o Passkey de 6 dígitos, derivando la "
            "Long Term Key (LTK) para descifrar toda la conexión BLE "
            "capturada."
        ),
        "how": [
            "1. Captura del tráfico BLE del emparejamiento (requiere sniffer "
            "de radio o una captura .cfile existente).",
            "2. Detección del SMP Pairing Request/Confirm/Random: si el "
            "método es Just Works, el TK es 0; si es Passkey, se fuerza "
            "bruta el PIN de 6 dígitos (máx. 10^6 combinaciones, "
            "verificando el valor confirm).",
            "3. Con el TK, se deriva el STK y luego la LTK del mensaje "
            "SMP Encryption Information.",
            "4. Con la LTK se descifra el resto de la captura en frío.",
        ],
        "impact": (
            "Descifrado offline de capturas BLE emparejadas con legacy "
            "pairing. Los dispositivos modernos con LE Secure Connections "
            "son inmunes (ECDH P-256)."
        ),
        "mitigation": [
            "Usar LE Secure Connections (BLE 4.2+) en lugar de legacy "
            "pairing.",
            "Evitar Just Works en productos que manejen datos sensibles: "
            "usar passkey/Numeric Comparison con autenticación.",
            "Para auditoría: capturar el propio emparejamiento de laboratorio "
            "y verificar que la LTK no sea derivable (modo simulado aquí).",
        ],
        "references": [
            "https://github.com/mikeryan/crackle",
            "Mike Ryan — 'Cracking Bluetooth Pairing' (USENIX 2013)",
        ],
    },
    "btlejack": {
        "title": "BTLEJack — sniffing e inyección de conexiones BLE activas",
        "what": (
            "BTLEJack es una herramienta de sniffing/inyección BLE: "
            "sincroniza con una conexión BLE activa (conocida su Access "
            "Address), sigue los saltos de canal (channel hopping map) y "
            "permite secuestrar la conexión o inyectar paquetes. Este "
            "módulo integra su flujo de trabajo en modo simulado o con "
            "hardware nRF52840/Micro:Bit."
        ),
        "how": [
            "1. Escaneo del canal de advertising para detectar conexiones "
            "(Access Addresses de 32 bits visibles en el paquete CONNECT).",
            "2. Sincronización con la conexión: seguir el hop map y el "
            "timing de la conexión activa.",
            "3. Sniffing de paquetes de datos (en claro si la conexión no "
            "está cifrada).",
            "4. Hijack: envío de paquetes con el mismo AA+timing para "
            "ganar el rol de master o esclavo (solo con hardware de radio "
            "adecuado).",
        ],
        "impact": (
            "En conexiones BLE sin cifrar: lectura de tráfico y secuestro "
            "de la conexión. Con cifrado, requiere combinar con crackeo de "
            "LTK (p.ej. crackle). Herramienta de laboratorio."
        ),
        "mitigation": [
            "Cifrar SIEMPRE las conexiones BLE GATT (aunque los datos sean "
            "'inofensivos': el cifrado evita el hijack).",
            "Rotar direcciones (RPA) para dificultar el re-tracking.",
            "En auditoría: verificar que las conexiones de producto usen "
            "encryption desde el primer paquete de datos.",
        ],
        "references": [
            "https://github.com/virtualabs/btlejack",
        ],
    },
    "btspam": {
        "title": "BTSpam — inundación de paquetes (3 técnicas)",
        "what": (
            "Módulo auxiliar de stress-test que inunda dispositivos "
            "descubribles con tráfico de pairing/inquiry/OBEX para medir "
            "su resiliencia a condiciones de radio hostiles. Es el "
            "equivalente Bluetooth de un stress test de disponibilidad."
        ),
        "how": [
            "1. Escaneo de dispositivos en el rango (o target fijo).",
            "2. Selección de técnica: inquiry flood, pairing requests "
            "repetidos o OBEX push masivo.",
            "3. Envío concurrente por hilos midiendo respuestas y caídas.",
        ],
        "impact": (
            "Denegación de servicio de proximidad. Útil para medir el "
            "timeout de recuperación del stack del objetivo."
        ),
        "mitigation": [
            "Modo no descubrible evita ser objetivo del flood.",
            "Los stacks modernos limitan peticiones entrantes por minuto "
            "(verificar el comportamiento del propio producto).",
            "Uso legítimo: probar SOLO hardware propio en laboratorio.",
        ],
        "references": [],
    },
    "autopilot": {
        "title": "Autopilot — pipeline de auditoría de 4 fases",
        "what": (
            "Autopilot encadena el flujo completo de auditoría: escaneo → "
            "detección de vulnerabilidades → ejecución de checks sugeridos → "
            "reporte. Es el modo recomendado para una primera evaluación de "
            "un entorno de laboratorio."
        ),
        "how": [
            "1. FASE SCAN: descubre dispositivos BR/EDR y BLE cercanos.",
            "2. FASE DETECT: ejecuta el escáner de vulnerabilidades (13+ "
            "checks) sobre los objetivos encontrados.",
            "3. FASE ATTACK: sugiere y ejecuta los checks/ataques no "
            "intrusivos aplicables según la pila detectada.",
            "4. FASE REPORT: genera el reporte HTML/JSON de la auditoría.",
        ],
        "impact": (
            "No es un ataque: es un orquestador. El impacto corresponde a "
            "los módulos que ejecute (por defecto, los no intrusivos)."
        ),
        "mitigation": [
            "Uso exclusivo en laboratorio o con autorización expresa del "
            "propietario de los dispositivos.",
            "Revisar el reporte generado para priorizar parcheo.",
        ],
        "references": [],
    },
    "scan": {
        "title": "Device Scanner — descubrimiento BR/EDR + BLE",
        "what": (
            "Escáner de dispositivos: usa inquiry clásico (hcitool/bluetoothctl) "
            "y BLE (bleak) para descubrir dispositivos cercanos con su "
            "nombre, clase, RSSI y tipo."
        ),
        "how": [
            "1. Verifica el adaptador local y su estado.",
            "2. Lanza inquiry BR/EDR y/o escaneo BLE (passive/active "
            "según config).",
            "3. Deduplica y clasifica los hallazgos (clase de dispositivo, "
            "servicios anunciados).",
        ],
        "impact": "Pasivo/solo lectura. Ningún impacto en los objetivos.",
        "mitigation": [
            "Los dispositivos en modo no descubrible no aparecen en el "
            "escaneo (defensa base contra reconnaissance).",
        ],
        "references": [],
    },
    "services": {
        "title": "Service Scanner — enumeración SDP/GATT",
        "what": (
            "Enumera los servicios de un objetivo: SDP en BR/EDR "
            "(sdptool browse) y GATT en BLE (bleak), identificando perfiles "
            "expuestos (SPP, OBEX, A2DP, HID...) y sus canales RFCOMM."
        ),
        "how": [
            "1. Conecta al objetivo y consulta el registro SDP / árbol GATT.",
            "2. Clasifica cada servicio con un nivel de riesgo según el "
            "perfil (SPP/OBEX sin auth = riesgo alto).",
            "3. Devuelve el mapa de canales para los módulos de auditoría.",
        ],
        "impact": "Enumeración pasiva; registra una conexión puntual.",
        "mitigation": [
            "No exponer perfiles SPP/OBEX innecesarios; exigir "
            "autenticación para el acceso a servicios.",
        ],
        "references": [],
    },
    "vuln": {
        "title": "Vulnerability Scanner — 13+ checks de CVEs Bluetooth",
        "what": (
            "Ejecuta checks no intrusivos de vulnerabilidades conocidas "
            "(BlueBorne, KNOB, BlueSmack, BTJacking, SSP bypass...) sobre "
            "un objetivo: fingerprinting de pila, servicios expuestos y "
            "comportamiento ante peticiones de prueba."
        ),
        "how": [
            "1. Recoge la huella del objetivo (fabricante, servicios, "
            "versión de pila cuando es accesible).",
            "2. Ejecuta cada check aplicable con peticiones seguras "
            "(ping L2CAP, petición SDP, negotiation probe).",
            "3. Reporta vulnerabilidades probables con su CVE y severidad.",
        ],
        "impact": (
            "Checks diseñados para no interrumpir el objetivo; igualmente "
            "úselo solo sobre dispositivos autorizados."
        ),
        "mitigation": [
            "Ejecutar este escáner periódicamente sobre el propio "
            "inventario es la mejor defensa: prioriza parcheo por severidad.",
        ],
        "references": [],
    },
    "keystroke": {
        "title": "Keystroke Injection — HID over GATT (laboratorio)",
        "what": (
            "Módulo de explotación del perfil HID: prepara y (con hardware "
            "adecuado) inyecta pulsaciones de teclado en un host que haya "
            "emparejado un teclado BLE falso. Requiere /dev/hidg0 "
            "(gadget HID) o un dispositivo BLE actuando como teclado."
        ),
        "how": [
            "1. Se empareja un teclado controlado por el auditor con el "
            "host objetivo (paso previo, fuera de este módulo).",
            "2. El módulo compone el reporte HID de las pulsaciones.",
            "3. Con gadget HID: envía por /dev/hidg0; con BLE: escribe en "
            "la característica HID report del teclado emulado.",
        ],
        "impact": (
            "Ejecución de comandos en el host emparejado. Solo aplica a "
            "vínculos que el auditor ya controla — demostración de riesgo "
            "de teclados BLE de dudosa procedencia."
        ),
        "mitigation": [
            "No emparejar teclados desconocidos; desemparejar vínculos HID "
            "no usados.",
            "En producto: exigir Numeric Comparison (no Just Works) para "
            "el perfil HID.",
        ],
        "references": [],
    },
    "l2cap_fuzz": {
        "title": "L2CAP Fuzzer — robustez de la pila Bluetooth",
        "what": (
            "Fuzzer de protocolo: envía paquetes L2CAP malformados (cabeceras "
            "inválidas, longitudes inconsistentes, comandos signal "
            "desconocidos) a un objetivo de laboratorio y detecta crashes "
            "o reinicios del stack."
        ),
        "how": [
            "1. Conecta un canal L2CAP al objetivo.",
            "2. Genera casos de prueba (mutación de cabeceras CID/len y "
            "payloads de signal commands).",
            "3. Envía cada caso midiendo si la conexión sobrevive.",
            "4. Reporta los casos que matan la conexión (crash/reset).",
        ],
        "impact": (
            "Puede reiniciar el objetivo (DoS). Diseñado para bancos de "
            "prueba: solo contra hardware propio."
        ),
        "mitigation": [
            "Integrar fuzzing L2CAP en el CI del firmware antes de "
            "desplegar productos.",
            "Los stacks actualizados validan longitudes/IDs y descartan "
            "paquetes malformados sin crash.",
        ],
        "references": [],
    },
    "rfcomm_shell": {
        "title": "RFCOMM Shell — acceso a consola serie SPP",
        "what": (
            "Busca canales RFCOMM (SPP) abiertos en el objetivo y los usa "
            "como consola serie: si un dispositivo expone SPP sin "
            "autenticación, el auditor obtiene la misma interfaz que el "
            "fabricante reservó para diagnóstico."
        ),
        "how": [
            "1. Escaneo de canales RFCOMM del objetivo (bind/release "
            "progresivo).",
            "2. Bind del canal abierto a /dev/rfcomm0.",
            "3. La consola del dispositivo queda accesible como puerto "
            "serie (screen /dev/rfcomm0).",
        ],
        "impact": (
            "Acceso a consola de diagnóstico de dispositivos embebidos mal "
            "asegurados. En hardware moderno SPP exige emparejamiento."
        ),
        "mitigation": [
            "Nunca exponer SPP de diagnóstico sin autenticación en "
            "producto.",
            "Auditar el inventario IoT con este módulo para detectar SPP "
            "abiertos.",
        ],
        "references": [],
    },
    "demo_scanner": {
        "title": "Demo Scanner — ejemplo de plugin externo",
        "what": (
            "Plugin de demostración del sistema de extensión: muestra cómo "
            "un módulo externo (directorio plugins/ o entry point de pip) "
            "se integra con el mismo contrato que los módulos nativos "
            "(BaseModule + shape de resultado {success, data, error})."
        ),
        "how": [
            "1. bluesky descubre el plugin en plugins/ (PLUGIN_INFO) o via "
            "entry points 'bluesky.modules'.",
            "2. Valida la interfaz (run/get_info) y lo registra junto a los "
            "nativos sin sobrescribirlos.",
            "3. 'run' del plugin se ejecuta igual que un módulo nativo.",
        ],
        "impact": (
            "Ninguno: es un ejemplo didáctico de integración. Útil como "
            "plantilla para desarrollar plugins propios de auditoría."
        ),
        "mitigation": [
            "Solo cargar plugins de fuentes de confianza: se ejecutan con "
            "los mismos privilegios que bluesky.",
            "Revisar el código de un plugin antes de instalarlo en el "
            "entorno de auditoría.",
        ],
        "references": [],
    },
}


# ─── API ────────────────────────────────────────────────────────────────────

def get_education(module_name: str) -> Optional[Dict]:
    """Retorna el contenido educativo de un módulo (None si no existe).

    Tolerante a entradas: acepta 'attack/knob', 'ATTACK/KNOB', 'knob '...
    """
    if not isinstance(module_name, str):
        return None
    name = module_name.strip().lower()
    # Normalizar prefijos tipo 'attack/', 'scanner/', 'exploit/', 'vuln/'
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    # Alias de módulos registrados con otro nombre
    aliases = {"keystroke_injection": "keystroke", "device_scanner": "scan",
               "service_scanner": "services"}
    name = aliases.get(name, name)
    if name is None:
        return None
    return EDU_DB.get(name)


def covered_modules() -> List[str]:
    """Lista ordenada de módulos con contenido educativo."""
    return sorted(EDU_DB.keys())


def format_education_plain(entry: Dict) -> str:
    """Render plano (sin Rich) de una entrada educativa."""
    if not isinstance(entry, dict) or not entry.get("title"):
        return "  Sin contenido educativo disponible"
    lines = []
    lines.append(f"  {entry.get('title', '')}")
    lines.append("")
    lines.append("  QUÉ ES")
    lines.append(f"    {entry.get('what', '')}")
    lines.append("")
    lines.append("  CÓMO FUNCIONA (paso a paso)")
    for step in entry.get("how", []):
        lines.append(f"    {step}")
    lines.append("")
    lines.append("  IMPACTO")
    lines.append(f"    {entry.get('impact', '')}")
    lines.append("")
    lines.append("  MITIGACIÓN (cómo defenderse)")
    for m in entry.get("mitigation", []):
        lines.append(f"    • {m}")
    refs = entry.get("references", [])
    if refs:
        lines.append("")
        lines.append("  REFERENCIAS")
        for r in refs:
            lines.append(f"    - {r}")
    return "\n".join(lines)


def format_education_rich(entry: Dict, console) -> None:
    """Render con Rich (Paneles) de una entrada educativa."""
    from rich.panel import Panel
    from rich.text import Text

    title = entry.get("title", "Módulo")
    console.print(Panel(
        Text(entry.get("what", ""), justify="left"),
        title=f"[bold cyan]{title}[/]",
        subtitle="[dim]modo educativo[/]",
        border_style="cyan",
    ))

    how_lines = "\n".join(entry.get("how", []))
    console.print(Panel(
        Text(how_lines, justify="left"),
        title="[bold]Cómo funciona (paso a paso)[/]",
        border_style="blue",
    ))

    console.print(Panel(
        Text(entry.get("impact", ""), justify="left"),
        title="[bold yellow]Impacto[/]",
        border_style="yellow",
    ))

    mit_lines = "\n".join(f"• {m}" for m in entry.get("mitigation", []))
    console.print(Panel(
        Text(mit_lines, justify="left"),
        title="[bold green]Mitigación — cómo defenderse[/]",
        border_style="green",
    ))

    refs = entry.get("references", [])
    if refs:
        console.print(Panel(
            Text("\n".join(f"- {r}" for r in refs), justify="left"),
            title="[dim]Referencias[/]",
            border_style="dim",
        ))
