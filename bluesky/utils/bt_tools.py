"""Herramientas Bluetooth de bajo nivel compartidas por los módulos de ataque.

Agrupa las operaciones HCI comunes (apertura/cierre de socket raw) y el
mensaje estándar de "scapy no disponible" para que los módulos KNOB, BLUFFS,
Sweyntooth y Crackle no dupliquen la misma lógica. scapy es una dependencia
opcional: cuando no está instalada, :func:`open_hci_socket` devuelve ``None``
y los módulos degradan a su modo pasivo/simulado.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

__all__ = ["open_hci_socket", "close_hci_socket", "scapy_unavailable_message"]

try:
    from scapy.layers.bluetooth import BluetoothHCISocket
except ImportError:  # scapy es opcional; ver docstring del módulo
    BluetoothHCISocket = None


def open_hci_socket(device: str = "hci0"):
    """Abre un socket HCI raw sobre el dispositivo indicado.

    Args:
        device: nombre de la interfaz HCI (p. ej. ``"hci0"``); el
            identificador numérico se extrae del sufijo.

    Returns:
        El socket abierto, o ``None`` si no pudo abrirse (scapy ausente,
        interfaz inexistente o sin permisos). Los callers deben tratar un
        valor falsy como "socket no disponible".
    """
    try:
        dev_id = int(device.replace("hci", ""))
        return BluetoothHCISocket(dev_id)
    except Exception as e:
        log.warning(f"No se pudo abrir HCI socket {device}: {e}")
        return None


def close_hci_socket(socket) -> None:
    """Cierra un socket HCI de forma segura; tolera ``None`` y errores."""
    if socket:
        try:
            socket.close()
        except Exception:
            pass


def scapy_unavailable_message(module: str, alternative: str = "") -> str:
    """Mensaje estándar para resultados cuyo modo activo requiere scapy.

    Formato "honesto" del proyecto: fallo explícito con la dependencia
    que falta y la alternativa pasiva si existe.

    Args:
        module: nombre del módulo tal como debe aparecer en el mensaje
            (p. ej. ``"KNOB activo"``).
        alternative: alternativa pasiva opcional para el usuario.

    Returns:
        Mensaje multilínea listo para ``result["data"]["message"]``.
    """
    msg = f"❌ {module} requiere scapy (no instalado).\n"
    msg += "   Instala: pip install scapy"
    if alternative:
        msg += f"\n   Alternativa: {alternative}"
    return msg
