"""
Bluesky - Bluetooth Security Auditing Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Bluesky es un framework de auditoría Bluetooth tipo Metasploit.
Soporta 15+ módulos de ataque, 3 escáneres, 3 exploits, escáner de
vulnerabilidades unificado (13+ checks), consola interactiva REPL,
dashboard web (Flask), y autopilot automatizado (scan→detect→attack→report).

Compatible con Windows, Linux, Termux (Android) y WSL.

Uso básico:
    bluesky console                    → Consola interactiva
    bluesky scan                       → Escanear dispositivos Bluetooth
    bluesky attack <mod>               → Ejecutar un ataque específico
    bluesky vuln <target>              → Escanear vulnerabilidades
    bluesky auto [target]              → Autopilot completo
    bluesky report                     → Generar reporte de auditoría
    bluesky list                       → Listar módulos disponibles
    bluesky web                        → Dashboard web (Flask)
    bluesky spam <target>              → BTSpam flood

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
