"""
Check registry and auto-discovery.

Importing this package triggers registration of all built-in checks.
"""

# Auto-import all check modules to trigger @CheckRegistry.register decorators
import importlib
import pkgutil

import gcp_abuse_scanner.checks.common as _cmn_pkg
import gcp_abuse_scanner.checks.crypto_mining as _cm_pkg
import gcp_abuse_scanner.checks.gemini_abuse as _gem_pkg
from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry

for _pkg in [_cm_pkg, _gem_pkg, _cmn_pkg]:
    for _importer, _modname, _ispkg in pkgutil.iter_modules(_pkg.__path__):
        importlib.import_module(f"{_pkg.__name__}.{_modname}")

__all__ = ["BaseCheck", "CheckRegistry"]
