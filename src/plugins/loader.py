from __future__ import annotations
"""TRACE OSINT Copilot - Plugin Loader.

Discovers and loads plugins from the plugins/ directory.
Each plugin is a Python module with a class that extends BasePlugin.
"""

import sys
import importlib
import pkgutil
from pathlib import Path
from typing import Optional

from src.plugins.base import BasePlugin
from src.config import PROJECT_ROOT

PLUGINS_DIR = PROJECT_ROOT / "plugins"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def discover_plugins() -> list[BasePlugin]:
    """Discover and instantiate all enabled plugins from plugins/ directory."""
    plugins: list[BasePlugin] = []

    if not PLUGINS_DIR.exists():
        return plugins

    for finder, name, ispkg in pkgutil.iter_modules([str(PLUGINS_DIR)]):
        if name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"plugins.{name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin):
                    instance = attr()
                    if instance.enabled:
                        plugins.append(instance)
        except Exception:
            pass

    return plugins


def run_collection_plugins(case) -> list:
    """Run all collection plugins and return their findings."""
    from src.models import Finding
    all_findings: list[Finding] = []

    for plugin in discover_plugins():
        try:
            findings = plugin.collect(case)
            if findings:
                all_findings.extend(findings)
        except Exception:
            pass

    return all_findings


def get_plugin_names() -> list[str]:
    """Return names of all discovered plugins."""
    return [p.name for p in discover_plugins()]
