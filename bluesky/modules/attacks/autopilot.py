"""
Autopilot - Ejecución automatizada completa.
Flujo: Scan → Vuln Detection → Auto-Exploit → Report

Modos:
  - full:   Escaneo completo + detección + explotación + reporte
  - detect: Solo detección de vulnerabilidades
  - attack: Solo fase de ataque (asume que ya se detectaron)

Requiere: ModuleEngine para cargar módulos dinámicamente.
"""

import time
import sys
import subprocess
from typing import Optional, List, Dict
from datetime import datetime
from pathlib import Path

from bluesky.core.engine import BaseModule


class Autopilot(BaseModule):
    """Autopilot - Ejecuta automáticamente escaneo → detección de vulns → ataques → reporte."""

    name = "autopilot"
    description = "Autopilot: Escaneo → Detección de vulnerabilidades → Ataques → Reporte automatizado"
    author = "Bluesky Project"
    version = "1.0.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "critical"

    module_options = {
        "TARGET": "MAC del dispositivo (vacío = escanear todos)",
        "MODE": "full | detect | attack (default: full)",
        "CHAIN": "Módulos a ejecutar separados por coma (default: auto-selección según vulns)",
        "REPORT": "Generar reporte HTML: true | false (default: true)",
        "TIMEOUT": "Timeout por módulo en segundos (default: 30)",
    }

    # Cadena por defecto para modo attack
    DEFAULT_ATTACK_CHAIN = [
        "blueborne", "knob", "bias", "bluffs", "whisperpair",
        "blesa", "sweyntooth", "bluefrag", "crackle",
    ]

    def run(self):
        """Ejecuta el pipeline completo autopilot."""
        target = self.target
        mode = self.options.get("MODE", "full").lower()
        custom_chain = self.options.get("CHAIN", "")
        generate_report = self.options.get("REPORT", "true").lower() == "true"
        timeout = int(self.options.get("TIMEOUT", "30"))

        self.result["data"]["mode"] = mode
        self.result["data"]["start_time"] = datetime.now().isoformat()

        from bluesky.core.engine import ModuleEngine
        from bluesky.core.session import Session
        self.engine = ModuleEngine()
        self.session = Session("autopilot_session")
        self.module_timeout = timeout

        try:
            # ── FASE 1: Escaneo ──────────────────────────────────────
            self.result["data"]["current_step"] = "Escaneando dispositivos..."
            print(f"\n  {'='*55}")
            print(f"  ⚡ BLUESKY AUTOPILOT v2.0")
            print(f"  {'='*55}")
            print(f"  Modo:    {mode.upper()}")
            print(f"  Target:  {target or 'AUTO (todos)'}")
            print(f"  {'='*55}\n")

            targets = self._phase_scan(target)
            if not targets:
                self.result["error"] = "No se encontraron dispositivos"
                self.result["success"] = False
                return self.result

            self.result["data"]["targets"] = targets

            # ── FASE 2: Detección de vulnerabilidades ───────────────
            all_vulns = {}
            for t in targets:
                print(f"\n  📋 Analizando vulnerabilidades de {t['name']} ({t['mac']})...")
                vulns = self._phase_detect(t['mac'])
                all_vulns[t['mac']] = vulns
                self.result["data"][f"vulns_{t['mac']}"] = vulns

            if mode == "detect":
                self.result["data"]["summary"] = self._format_detect_summary(targets, all_vulns)
                self.result["success"] = True
                return self.result

            # ── FASE 3: Auto-Exploit ────────────────────────────────
            if custom_chain:
                chain = [c.strip() for c in custom_chain.split(",")]
            else:
                chain = self._build_attack_chain(all_vulns)

            self.result["data"]["chain"] = chain
            results = self._phase_attack(targets, chain, all_vulns)
            self.result["data"]["results"] = results

            # ── FASE 4: Reporte ─────────────────────────────────────
            if generate_report:
                report_path = self._phase_report(targets, results, all_vulns)
                self.result["data"]["report_path"] = report_path

            # Métricas finales
            total_attacks = sum(len(r) for r in results.values())
            successes = sum(
                1 for target_results in results.values()
                for r in target_results if r.get("success")
            )

            self.result["data"]["stats"] = {
                "targets": len(targets),
                "attacks_total": total_attacks,
                "attacks_successful": successes,
                "vulnerabilities_found": sum(
                    len(v) for vuln_list in all_vulns.values()
                    for v in vuln_list
                ),
            }

            self.result["data"]["summary"] = self._format_summary(
                targets, results, all_vulns, successes, total_attacks
            )
            self.result["success"] = True

        except Exception as e:
            self.result["error"] = f"Error en Autopilot: {e}"
            self.result["success"] = False

        return self.result

    # ─── FASE 1: Escaneo ──────────────────────────────────────────────

    def _phase_scan(self, target: str) -> List[dict]:
        """Escanea dispositivos Bluetooth."""
        if target:
            print(f"  [1/4] 📡 Usando target específico: {target}")
            return [{"mac": target, "name": target, "type": "unknown"}]

        print(f"  [1/4] 📡 Escaneando dispositivos Bluetooth...")
        devices = []

        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["bluetoothctl", "--timeout", "6", "scan", "on"],
                    capture_output=True, text=True, timeout=10
                )
                seen = set()
                for line in result.stdout.split("\n"):
                    if "Device" in line:
                        parts = line.split("Device", 1)[1].strip().split(" ", 1)
                        mac = parts[0] if len(parts) > 0 else ""
                        name = parts[1] if len(parts) > 1 else "Unknown"
                        if mac and ":" in mac and mac not in seen:
                            seen.add(mac)
                            devices.append({"mac": mac, "name": name, "type": "classic"})

                # Obtener información detallada
                for d in devices[:3]:  # Solo primeros 3 para no saturar
                    try:
                        result = subprocess.run(
                            ["bluetoothctl", "info", d["mac"]],
                            capture_output=True, text=True, timeout=5
                        )
                        for line in result.stdout.split("\n"):
                            if "Name:" in line:
                                d["name"] = line.split("Name:")[1].strip()
                    except Exception:
                        pass

        except Exception as e:
            print(f"  ⚠️ Error en escaneo: {e}")

        if devices:
            print(f"  ✅ {len(devices)} dispositivo(s) encontrado(s):")
            for d in devices[:5]:
                print(f"     🔵 {d['mac']} - {d['name']}")
        else:
            print(f"  ⚠️ No se encontraron dispositivos")

        return devices

    # ─── FASE 2: Detección de vulnerabilidades ─────────────────────────

    def _phase_detect(self, target: str) -> List[dict]:
        """Ejecuta el escáner de vulnerabilidades."""
        print(f"  [2/4] 🔍 Escaneando vulnerabilidades de {target}...")

        try:
            from bluesky.modules.scanners.vuln_scanner import VulnScanner
            scanner = VulnScanner(target=target, options={"SCAN_TYPE": "full"})
            result = scanner.run()

            vulns = result.get("data", {}).get("vulnerabilities", [])
            found = [v for v in vulns if v.get("vulnerable", False)]

            if found:
                critical = [v for v in found if v["severity"] == "critical"]
                high = [v for v in found if v["severity"] == "high"]
                print(f"     ✅ {len(found)} vulnerabilidad(es) encontrada(s):")
                print(f"        🔴 {len(critical)} críticas  🟡 {len(high)} altas")
                for v in found[:5]:
                    print(f"        • {v['id']}: {v['name'][:60]}")
                if len(found) > 5:
                    print(f"        ... y {len(found)-5} más")
            else:
                print(f"     ✅ No se encontraron vulnerabilidades")

            return found

        except ImportError:
            print(f"     ⚠️ Escáner de vulnerabilidades no disponible")
            return []
        except Exception as e:
            print(f"     ⚠️ Error en detección: {e}")
            return []

    # ─── FASE 3: Auto-Exploit ──────────────────────────────────────────

    def _build_attack_chain(self, all_vulns: dict) -> List[str]:
        """Construye cadena de ataque basada en vulnerabilidades encontradas."""
        used = set()
        chain = []

        # Priorizar por severidad
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Recoger todos los módulos sugeridos
        candidates = []
        for mac, vulns in all_vulns.items():
            for v in vulns:
                if v.get("vulnerable") and v.get("module"):
                    sev_rank = severity_order.get(v["severity"], 99)
                    candidates.append((sev_rank, v["module"], v["id"]))

        candidates.sort()

        for _, mod, vuln_id in candidates:
            if mod not in used:
                chain.append(mod)
                used.add(mod)

        # Si no hay candidatos, usar cadena por defecto
        if not chain:
            chain = list(self.DEFAULT_ATTACK_CHAIN)

        return chain

    def _phase_attack(self, targets: List[dict], chain: List[str],
                      all_vulns: dict) -> Dict[str, List[dict]]:
        """Ejecuta la cadena de ataques contra los targets."""
        results = {}

        print(f"\n  [3/4] ⚔️ Ejecutando cadena de ataques...")
        print(f"  Chain: {' → '.join(chain)}")
        print()

        for target_info in targets:
            mac = target_info["mac"]
            results[mac] = []

            for step, module_name in enumerate(chain, 1):
                print(f"     [{step}/{len(chain)}] {module_name} → {mac}...")

                result = self._run_single_module(module_name, mac)

                status = "✅" if result.get("success") else "⚠️"
                print(f"       {status} {module_name} completado")

                results[mac].append({
                    "module": module_name,
                    "target": mac,
                    "success": result.get("success", False),
                    "data": result.get("data", {}),
                    "error": result.get("error"),
                })

        return results

    def _run_single_module(self, module_name: str, target: str) -> dict:
        """Ejecuta un módulo individual."""
        try:
            if hasattr(self, 'engine') and self.engine:
                return self.engine.run_module(module_name, target=target)
            return {"success": False, "error": "Engine no disponible"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ─── FASE 4: Reporte ──────────────────────────────────────────────

    def _phase_report(self, targets: List[dict], results: Dict[str, List[dict]],
                      all_vulns: dict) -> str:
        """Genera reporte HTML del autopilot."""
        print(f"  [4/4] 📊 Generando reporte...")

        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"autopilot_{timestamp}.html"

        target_rows = ""
        for t in targets:
            vulns = all_vulns.get(t["mac"], [])
            found = [v for v in vulns if v.get("vulnerable")]
            vuln_str = ", ".join(v["id"] for v in found[:5])
            if len(found) > 5:
                vuln_str += f" y {len(found)-5} más"

            target_rows += f"""
            <tr>
                <td>{t['name']}</td>
                <td><code>{t['mac']}</code></td>
                <td>{len(found)}</td>
                <td>{vuln_str or 'Ninguna'}</td>
            </tr>"""

        result_rows = ""
        for mac, module_results in results.items():
            for r in module_results:
                color = "green" if r.get("success") else "orange"
                status_icon = "✅" if r.get("success") else "⚠️"
                result_rows += f"""
            <tr>
                <td><code>{mac}</code></td>
                <td>{r['module']}</td>
                <td style="color:{color}">{status_icon} {'Éxito' if r.get('success') else 'Completado'}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Bluesky Autopilot Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; flex: 1; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #16213e; border-radius: 10px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #0f3460; color: #00d4ff; }}
        tr:hover {{ background: #1a1a3e; }}
        code {{ background: #0f3460; padding: 2px 6px; border-radius: 4px; color: #00d4ff; }}
    </style>
</head>
<body>
<div class="container">
    <h1>⚡ Bluesky Autopilot Report</h1>
    <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{len(targets)}</div>
            <div>Targets</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{sum(len(r) for r in results.values())}</div>
            <div>Ataques</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{sum(sum(1 for r in res if r.get('success')) for res in results.values())}</div>
            <div>Exitosos</div>
        </div>
    </div>

    <h2>🎯 Targets</h2>
    <table>
        <thead><tr><th>Nombre</th><th>MAC</th><th>Vulns</th><th>Detalle</th></tr></thead>
        <tbody>{target_rows}</tbody>
    </table>

    <h2>⚔️ Resultados</h2>
    <table>
        <thead><tr><th>Target</th><th>Módulo</th><th>Estado</th></tr></thead>
        <tbody>{result_rows}</tbody>
    </table>

    <p style="margin-top:30px;color:#666;text-align:center;">
        Generado por <strong>Bluesky Autopilot v2.0</strong>
    </p>
</div>
</body>
</html>"""

        report_path.write_text(html, encoding="utf-8")
        print(f"  ✅ Reporte generado: {report_path}")
        return str(report_path)

    # ─── Formateo ──────────────────────────────────────────────────────

    def _format_detect_summary(self, targets: List[dict], all_vulns: dict) -> str:
        """Resumen del modo detect."""
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║     🛡️  BLUESKY AUTOPILOT - DETECT MODE                    ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            "📊  VULNERABILIDADES ENCONTRADAS:",
            "───────────────────────────────────────────────────────────────",
        ]

        for t in targets:
            vulns = all_vulns.get(t["mac"], [])
            found = [v for v in vulns if v.get("vulnerable")]
            lines.append(f"\n  🎯 {t['name']} ({t['mac']})")
            if found:
                for v in found:
                    icon = "🔴" if v["severity"] == "critical" else "🟡"
                    lines.append(f"    {icon} {v['id']}: {v['name']}")
                    if v.get('cve', 'N/A') != 'N/A':
                        lines.append(f"       CVE: {v.get('cve', 'N/A')}")
                    lines.append(f"       → bluesky attack {v['module']} {t['mac']}")
            else:
                lines.append("    ✅ Sin vulnerabilidades detectadas")

        lines.extend([
            "",
            "💡  Para auto-explotar:  bluesky auto <MAC>",
            "💡  Para ataque completo: bluesky auto <MAC> --mode attack",
        ])

        return "\n".join(lines)

    def _format_summary(self, targets: List[dict], results: Dict[str, List[dict]],
                        all_vulns: dict, successes: int, total: int) -> str:
        """Resumen final del autopilot."""
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║     ⚡  BLUESKY AUTOPILOT v2.0 - MISSION COMPLETE           ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            "📊  ESTADÍSTICAS FINALES:",
            "───────────────────────────────────────────────────────────────",
            f"  Targets procesados:  {len(targets)}",
            f"  Ataques ejecutados:  {total}",
            f"  Ataques exitosos:    {successes}",
            "",
            "🎯  DETALLE POR TARGET:",
            "───────────────────────────────────────────────────────────────",
        ]

        for t in targets:
            mac = t["mac"]
            target_results = results.get(mac, [])
            vulns = all_vulns.get(mac, [])
            found_vulns = [v for v in vulns if v.get("vulnerable")]

            lines.append(f"\n  {t['name']} ({mac}):")
            lines.append(f"    Ataques: {len(target_results)}")
            lines.append(f"    Exitosos: {sum(1 for r in target_results if r.get('success'))}")

            if found_vulns:
                lines.append(f"    Vulnerabilidades:")
                for v in found_vulns:
                    icon = "🔴" if v["severity"] == "critical" else "🟡"
                    lines.append(f"      {icon} {v['id']} ({v['severity']})")

        return "\n".join(lines)
