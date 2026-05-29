"""
Autopilot - Ejecución automatizada de ataques en cadena.
Escanea → Detecta → Explota dispositivos Bluetooth automáticamente.
"""

import time
import subprocess
from typing import Optional, List

from bluesky.core.engine import BaseModule


class Autopilot(BaseModule):
    """Autopilot - Ejecuta una batería completa de ataques Bluetooth automáticamente."""

    name = "autopilot"
    description = "Autopilot: Ejecuta automáticamente escaneo + detección de vulnerabilidades + ataques en cadena"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "high"

    # Cadena de ataques por defecto
    DEFAULT_CHAIN = [
        "scan",
        "blueborne",
        "whisperpair",
        "blesa",
        "sweyntooth",
        "bluejacking",
    ]

    def run(self):
        """Ejecuta la cadena de ataques automática."""
        target = self.target
        chain_names = self.options.get("chain", ",".join(self.DEFAULT_CHAIN))
        if isinstance(chain_names, str):
            chain_names = [c.strip() for c in chain_names.split(",")]

        self.result["data"]["chain"] = chain_names
        self.result["data"]["start_time"] = time.strftime("%H:%M:%S")
        chain_results = []

        print(f"\n  {'='*50}")
        print(f"  ⚡ BLUESKY AUTOPILOT")
        print(f"  {'='*50}")
        print(f"  Target: {target or 'AUTO (todos los dispositivos)'}")
        print(f"  Chain:  {' → '.join(chain_names)}")
        print(f"  {'='*50}\n")

        from bluesky.core.engine import ModuleEngine
        engine = ModuleEngine()
        discovered_targets = []

        for step, module_name in enumerate(chain_names, 1):
            step_target = target
            print(f"  [{step}/{len(chain_names)}] Ejecutando: {module_name}")

            # Si no hay target específico, usar targets descubiertos
            if not step_target and discovered_targets:
                for dt in discovered_targets:
                    result = self._run_module(engine, module_name, dt)
                    result["target"] = dt
                    chain_results.append(result)
                continue

            result = self._run_module(engine, module_name, step_target)
            chain_results.append({
                "module": module_name,
                "target": step_target or "auto",
                "result": result,
            })

            # Si el módulo descubrió dispositivos, guardarlos
            devices = result.get("data", {}).get("devices", [])
            if devices:
                for d in devices:
                    mac = d.get("mac", "")
                    name = d.get("name", "")
                    if mac and mac not in discovered_targets:
                        discovered_targets.append(mac)
                        print(f"     → Nuevo target: {name} ({mac})")

        # Resumen
        self.result["data"]["chain_results"] = chain_results
        self.result["data"]["total_steps"] = len(chain_names)
        self.result["data"]["targets_discovered"] = len(discovered_targets)
        self.result["data"]["end_time"] = time.strftime("%H:%M:%S")

        successes = sum(1 for r in chain_results if r.get("result", {}).get("success"))
        self.result["data"]["summary"] = (
            f"\n  {'='*50}\n"
            f"  📊 AUTOPILOT COMPLETED\n"
            f"  {'='*50}\n"
            f"  Pasos ejecutados: {len(chain_names)}\n"
            f"  Exitosos:         {successes}\n"
            f"  Targets encontrados: {len(discovered_targets)}\n"
            f"  {'='*50}"
        )

        # Consolidar vulnerabilidades
        all_vulns = []
        for r in chain_results:
            vulns = r.get("result", {}).get("data", {}).get("vulnerabilities", [])
            all_vulns.extend(vulns)
        if all_vulns:
            self.result["data"]["total_vulnerabilities"] = len(all_vulns)
            self.result["data"]["vulnerabilities"] = all_vulns

        self.result["success"] = True
        return self.result

    def _run_module(self, engine, module_name: str, target: str) -> dict:
        """Ejecuta un módulo individual con logging."""
        try:
            result = engine.run_module(module_name, target=target)
            status = "✅" if result.get("success") else "⚠️"
            print(f"     {status} {module_name} {'→ ' + target if target else ''}")

            # Mostrar resumen rápido
            data = result.get("data", {})
            for key in ("summary", "message", "warning"):
                val = data.get(key)
                if val and isinstance(val, str):
                    for line in val.split("\n")[:2]:
                        if line.strip():
                            print(f"       {line.strip()[:80]}")
            return result
        except Exception as e:
            print(f"     ❌ {module_name}: {e}")
            return {"success": False, "error": str(e), "data": {}}
