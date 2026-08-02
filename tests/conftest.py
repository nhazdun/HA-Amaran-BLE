"""Test bootstrap.

Registers ``custom_components.amaran_ble`` as a package whose ``__init__`` is
*not* executed. That keeps the protocol tests free of a Home Assistant
install, and doubles as an assertion that ``mesh/`` and ``amaran/`` carry no
Home Assistant imports of their own.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for name, path in (
    ("custom_components", ROOT / "custom_components"),
    ("custom_components.amaran_ble", ROOT / "custom_components" / "amaran_ble"),
):
    if name not in sys.modules:
        module = types.ModuleType(name)
        module.__path__ = [str(path)]
        module.__package__ = name
        sys.modules[name] = module
