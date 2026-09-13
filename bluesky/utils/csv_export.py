"""
CSV Export - Exportación de resultados de descubrimiento a CSV.

Genera CSV válido (RFC 4180 tolerante) a partir de la lista de
dispositivos que devuelve DeviceScanner, listo para abrir en hojas de
cálculo o adjuntar a un informe de cliente.

Uso:
    from bluesky.utils.csv_export import devices_to_csv

    csv_text = devices_to_csv(devices)
    Path("dispositivos.csv").write_text(csv_text, encoding="utf-8-sig")

Nota: para Excel en español es recomendable codificar con
"utf-8-sig" (BOM) de modo que los acentos y la ñ se muestren bien.
"""

import csv
import io
from typing import List

# Columnas del CSV de dispositivos (orden estable).
CSV_COLUMNS = ["mac", "name", "type", "vendor", "rssi", "paired"]


def _cell(value) -> str:
    """Convierte un valor arbitrario a celda CSV segura (None -> '')."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def devices_to_csv(devices: List[dict]) -> str:
    """
    Convierte una lista de dispositivos descubiertos en texto CSV.

    Los dispositivos vienen del resultado de DeviceScanner:
    ``{"mac": ..., "name": ..., "type": ..., "rssi": ...,
    "info": {"rssi": ..., "paired": ...}, "vendor": ...}``.
    Las entradas malformadas (no dict) se exportan como una fila con
    el valor crudo en la columna 'mac' y el resto vacío, en lugar de
    romper la exportación completa.

    Returns:
        Texto CSV con cabecera incluida (siempre, incluso sin datos).
    """
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    for dev in devices or []:
        if not isinstance(dev, dict):
            writer.writerow([_cell(dev)] + [""] * (len(CSV_COLUMNS) - 1))
            continue

        info = dev.get("info") if isinstance(dev.get("info"), dict) else {}
        rssi = dev.get("rssi")
        if rssi in (None, ""):
            rssi = info.get("rssi", "")
        paired = dev.get("paired")
        if paired is None:
            paired = info.get("paired", "")

        writer.writerow([
            _cell(dev.get("mac")),
            _cell(dev.get("name")),
            _cell(dev.get("type")),
            _cell(dev.get("vendor")),
            _cell(rssi),
            _cell(paired),
        ])

    return buf.getvalue()


def devices_from_scan_result(result: dict) -> List[dict]:
    """
    Extrae la lista de dispositivos de un resultado de módulo 'scan'.

    Tolerante a shapes antiguos o resultados fallidos: devuelve []
    cuando no hay dispositivos aprovechables.
    """
    if not isinstance(result, dict):
        return []
    data = result.get("data")
    if not isinstance(data, dict):
        return []
    devices = data.get("devices")
    if not isinstance(devices, list):
        return []
    return devices
