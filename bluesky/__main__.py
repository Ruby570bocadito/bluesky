#!/usr/bin/env python3
"""
Bluesky - Bluetooth Security Auditing Framework
Entry point for `python -m bluesky`
"""

import sys
from pathlib import Path

# Asegurar que el paquete bluesky se encuentra aunque no esté instalado vía pip
_THIS_DIR = Path(__file__).parent.parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from bluesky.cli import main

main()
