# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Plugin Base Interface.

All plugins must implement this interface to be discovered and executed.
Plugins are loaded from the plugins/ directory at runtime.
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.models import Case, Finding


class BasePlugin(ABC):
    """Abstract base class for TRACE plugins.

    Plugins can:
    - Add new collection sources
    - Add new analysis steps
    - Modify reports before output
    """

    name: str = "base_plugin"
    description: str = "Base plugin"
    version: str = "1.0.0"
    enabled: bool = True

    @abstractmethod
    def collect(self, case: Case) -> list[Finding]:
        """Run collection phase. Return new findings to add to the case."""
        return []

    def analyze(self, case: Case) -> Optional[dict]:
        """Run analysis phase. Return optional analysis results."""
        return None

    def on_report(self, case: Case, report: dict) -> dict:
        """Hook into report generation. Return modified report."""
        return report

    def __repr__(self) -> str:
        return f"<Plugin: {self.name} v{self.version}>"
