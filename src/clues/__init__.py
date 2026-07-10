from __future__ import annotations
"""TRACE OSINT Copilot - Clues Package.

Explicit clue parsing and classification for investigation inputs.
"""

from src.clues.parser import (
    classify_clue,
    detect_case_mode,
    parse_clues,
    is_common_name,
    COMMON_NAME_TOKENS,
)

__all__ = [
    "classify_clue",
    "detect_case_mode",
    "parse_clues",
    "is_common_name",
    "COMMON_NAME_TOKENS",
]
