"""TRACE OSINT Copilot - Configuration Package.

Centralized configuration, policy enforcement, and environment loading.
"""

from src.config.settings import (
    PROJECT_ROOT,
    CASES_DIR,
    OUTPUT_DIR,
    SRC_DIR,
    PolicyMode,
    BLOCKED_ACTIONS,
    ALLOWED_SOURCES,
    MAX_CONCURRENT_REQUESTS,
    REQUEST_TIMEOUT_SECONDS,
    DEFAULT_SEARCH_RESULTS,
    MAX_RETRIES,
    RETRY_DELAY_SECONDS,
    USE_CONCURRENT,
    CONFIDENCE_THRESHOLDS,
    get_env,
    get_provider_config,
    get_retrieval_config,
)

__all__ = [
    "PROJECT_ROOT",
    "CASES_DIR",
    "OUTPUT_DIR",
    "SRC_DIR",
    "PolicyMode",
    "BLOCKED_ACTIONS",
    "ALLOWED_SOURCES",
    "MAX_CONCURRENT_REQUESTS",
    "REQUEST_TIMEOUT_SECONDS",
    "DEFAULT_SEARCH_RESULTS",
    "MAX_RETRIES",
    "RETRY_DELAY_SECONDS",
    "USE_CONCURRENT",
    "CONFIDENCE_THRESHOLDS",
    "get_env",
    "get_provider_config",
    "get_retrieval_config",
]
