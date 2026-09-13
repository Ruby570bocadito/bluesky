"""
OUI Lookup - Identificación de fabricante a partir del prefijo MAC.

Base de datos OUI (Organizationally Unique Identifier) curada y 100%
offline, centrada en fabricantes habituales del ecosistema Bluetooth:
smartphones, audio, wearables, IoT y chipsets de radio.

Los prefijos se normalizan a "AA:BB:CC" (mayúsculas con dos puntos).
La base es un subconjunto curado: para cobertura completa se puede usar
la base pública de IEEE, pero esta implementación evita dependencias
externas y sirvió unificando la lógica dispersa por los backends.

Uso:
    from bluesky.utils.oui import lookup_vendor

    lookup_vendor("B8:27:EB:12:34:56")   # "Raspberry Pi Trading"
    lookup_vendor("no-mac")              # "" (o el default indicado)
"""

import re
from typing import Dict, Optional

# Prefijo (3 octetos) -> fabricante. Subconjunto curado offline.
OUI_DATABASE: Dict[str, str] = {
    "00:0A:AD": "HTC",
    "00:10:18": "Broadcom",
    "00:1A:7D": "Cambridge Silicon Radio (CSR)",
    "00:1B:63": "Apple",
    "00:23:76": "Samsung",
    "00:25:00": "Samsung",
    "00:26:37": "LG Electronics",
    "04:02:1E": "Google",
    "04:CB:1D": "Huawei",
    "08:00:46": "Sony",
    "08:74:02": "Xiaomi",
    "0C:9D:92": "OnePlus",
    "10:83:44": "Google",
    "14:3D:2E": "LG Electronics",
    "18:3E:2A": "Motorola",
    "18:87:96": "Samsung",
    "1C:9E:46": "LG Electronics",
    "20:17:C9": "Sony",
    "20:5E:4B": "Huawei",
    "20:F4:1B": "Google",
    "24:0A:C4": "Samsung",
    "24:46:C8": "Xiaomi",
    "28:6C:07": "Samsung",
    "28:CD:C1": "Raspberry Pi Trading",
    "2C:54:2D": "HTC",
    "30:07:4D": "Samsung",
    "30:3A:64": "Google",
    "34:23:87": "LG Electronics",
    "38:2C:4A": "Xiaomi",
    "38:4B:21": "Samsung",
    "3C:15:C2": "Apple",
    "3C:5A:37": "Huawei",
    "40:9F:38": "Motorola",
    "4C:AA:16": "Samsung",
    "50:1A:A5": "Sony",
    "54:0B:E0": "Huawei",
    "54:0B:F8": "Sony",
    "54:8D:5A": "LG Electronics",
    "58:68:7B": "Samsung",
    "5C:B9:01": "Xiaomi",
    "60:A4:D0": "Samsung",
    "64:66:B3": "Huawei",
    "68:54:1A": "Samsung",
    "6C:0E:0D": "OnePlus",
    "70:BF:92": "Motorola",
    "74:A7:05": "LG Electronics",
    "78:67:D7": "Samsung",
    "84:DB:2F": "Xiaomi",
    "88:32:9B": "Google",
    "88:35:4C": "Samsung",
    "88:66:A5": "Apple",
    "8C:45:00": "Samsung",
    "8C:8C:AA": "Samsung",
    "90:18:AE": "Google",
    "94:A1:B1": "Huawei",
    "94:CB:CD": "Samsung",
    "98:0C:82": "LG Electronics",
    "98:2B:C4": "Sony",
    "9C:20:7E": "Motorola",
    "9C:2A:70": "Samsung",
    "9C:57:AD": "Samsung",
    "A0:1D:48": "Samsung",
    "A0:7C:2F": "Sony",
    "A4:77:33": "Samsung",
    "A4:83:E7": "Apple",
    "A4:9B:4F": "Huawei",
    "A4:C3:F0": "LG Electronics",
    "A8:2B:B5": "Samsung",
    "AC:57:75": "LG Electronics",
    "AC:84:C6": "Samsung",
    "AC:87:A3": "Apple",
    "B0:1B:7D": "Samsung",
    "B0:4B:CF": "Xiaomi",
    "B4:0B:44": "Huawei",
    "B4:52:7D": "Samsung",
    "B8:09:8A": "Sony",
    "B8:27:EB": "Raspberry Pi Trading",
    "B8:6C:E8": "Samsung",
    "BC:76:70": "Google",
    "C0:21:0D": "Samsung",
    "C0:78:9F": "LG Electronics",
    "C4:17:FE": "Samsung",
    "C4:43:8F": "Huawei",
    "C8:94:02": "Huawei",
    "CC:3D:82": "Google",
    "D0:03:4B": "Apple",
    "D0:2A:42": "Samsung",
    "D0:53:49": "Motorola",
    "D4:67:E7": "Samsung",
    "D8:0B:9A": "Huawei",
    "D8:1C:79": "Samsung",
    "D8:3A:DD": "Raspberry Pi Trading",
    "D8:55:A3": "LG Electronics",
    "DC:0D:30": "Samsung",
    "DC:40:5F": "Sony",
    "DC:A6:32": "Raspberry Pi Trading",
    "E0:2C:12": "OnePlus",
    "E0:A0:30": "LG Electronics",
    "E4:4E:2D": "Motorola",
    "E4:5F:01": "Raspberry Pi Trading",
    "E8:50:8B": "Samsung",
    "EC:14:0E": "Huawei",
    "EC:1F:72": "Motorola",
    "F0:03:8C": "Samsung",
    "F0:18:98": "Apple",
    "F0:1D:BC": "Google",
    "F0:7B:CB": "Samsung",
    "F4:4E:FD": "Sony",
    "F4:8C:50": "Huawei",
    "F4:F5:D8": "Samsung",
    "F8:1E:DF": "Apple",
    "F8:2F:5C": "Huawei",
    "FC:61:3D": "Xiaomi",
    "FC:6E:1B": "Samsung",
}

# MAC normalizada: exactamente 12 dígitos hex.
_MAC_RE = re.compile(r"^[0-9A-F]{12}$")

# Separadores aceptados al normalizar: ':', '-', '.' y espacios.
_SEP_RE = re.compile(r"[\s:\-.]")

# Caché de resultados por MAC normalizada (evita re-calcular prefijos
# en escaneos con cientos de dispositivos).
_cache: Dict[str, str] = {}


def normalize_mac(mac: str) -> Optional[str]:
    """
    Normaliza una MAC a 12 hexadecimales mayúsculas sin separadores.

    Acepta formatos "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff",
    "AABB.CDD.EEF" o "AABBCCDDEEFF". Devuelve None si la entrada no
    tiene 12 dígitos hex válidos.
    """
    if not isinstance(mac, str):
        return None
    clean = _SEP_RE.sub("", mac).upper()
    if not _MAC_RE.match(clean):
        return None
    return clean


def _prefix_of(mac: str) -> Optional[str]:
    """Extrae el prefijo OUI 'AA:BB:CC' de una MAC arbitraria."""
    clean = normalize_mac(mac)
    if clean is None:
        return None
    return f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"


def lookup_vendor(mac: str, default: str = "") -> str:
    """
    Devuelve el fabricante asociado al prefijo OUI de la MAC.

    Args:
        mac: Dirección en cualquier formato habitual de separadores.
        default: Valor devuelto cuando la MAC es inválida o el prefijo
            no está en la base ("" por defecto; los backends de Termux
            usan "Unknown" por compatibilidad histórica).

    Returns:
        Nombre del fabricante o `default`.
    """
    prefix = _prefix_of(mac)
    if prefix is None:
        return default
    cached = _cache.get(prefix)
    if cached is not None:
        return cached
    vendor = OUI_DATABASE.get(prefix)
    # Solo se cachean los aciertos: el miss depende de `default` y no
    # debe contaminar consultas posteriores con otro default.
    if vendor is not None:
        _cache[prefix] = vendor
        return vendor
    return default


def annotate_devices(devices: list) -> list:
    """
    Añade la clave "vendor" a cada dispositivo de una lista de scan.

    Es tolerante con entradas malformadas (no dict, sin MAC): se
    devuelven intactas. Devuelve la misma lista (mutada) para poder
    usarse en línea.
    """
    for dev in devices:
        if isinstance(dev, dict) and dev.get("mac") and "vendor" not in dev:
            vendor = lookup_vendor(str(dev["mac"]))
            if vendor:
                dev["vendor"] = vendor
    return devices
