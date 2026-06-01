"""
Bluesky - Bluetooth Security Auditing Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Bluesky es un framework de auditoría Bluetooth de código abierto con
arquitectura modular tipo Metasploit. Unifica 15+ módulos de ataque,
3 escáneres, 3 exploits, un escáner de vulnerabilidades integrado
(13+ checks), consola interactiva REPL, dashboard web (Flask),
y autopilot automatizado de 4 fases (scan→detect→attack→report).

Compatibilidad multi-plataforma: Windows, Linux, Termux (Android) y WSL.

Uso básico:
    bluesky console                    → Consola interactiva
    bluesky scan                       → Escanear dispositivos Bluetooth
    bluesky attack <mod>               → Ejecutar un ataque específico
    bluesky vuln <target>              → Escanear vulnerabilidades (13+ checks)
    bluesky auto [target]              → Autopilot: scan→detect→attack→report
    bluesky spam <target>              → BTSpam flood (3 técnicas)
    bluesky list                       → Listar módulos disponibles
    bluesky info <mod>                 → Info detallada de un módulo
    bluesky report                     → Generar reporte de auditoría
    bluesky web                        → Dashboard web (Flask)
    bluesky config show                → Ver configuración
    bluesky session list               → Gestión de sesiones

Módulos de ataque: knob, bias, bluffs, blueborne, bluefrag, blesa,
sweyntooth, whisperpair, crackle, btlejack, bluejacking, bluesnarfing,
bluebugging, btspam.

Escáneres: device_scanner, service_scanner, vuln (13+ vulnerabilidades).

Exploits: keystroke_injection, l2cap_fuzz, rfcomm_shell.

Author: Bluesky Project
Version: 0.2.0
License: MIT
"""

__version__ = "0.2.0"
__author__ = "Bluesky Project"
__description__ = "Bluetooth Security Auditing Framework - Metasploit-style"

# Core components
from bluesky.core.engine import BaseModule, ModuleEngine

# CLI entry point
from bluesky.cli import main as cli_main
