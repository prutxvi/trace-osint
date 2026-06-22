"""TRACE OSINT Copilot - Configuration Module"""

import os
from pathlib import Path
from enum import Enum


def _load_dotenv():
    """Load .env file into environment variables."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value


_load_dotenv()


class PolicyMode(str, Enum):
    READ_ONLY = "READ_ONLY"
    RESTRICTED = "RESTRICTED"
    BLOCKED = "BLOCKED"


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CASES_DIR = PROJECT_ROOT / "cases"
OUTPUT_DIR = PROJECT_ROOT / "output"
SRC_DIR = PROJECT_ROOT / "src"

CASES_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


BLOCKED_ACTIONS = [
    "private_account_access",
    "login_abuse",
    "credential_harvesting",
    "account_recovery_misuse",
    "phishing",
    "malware_distribution",
    "exploitation",
    "breach_database_scraping",
    "stealth_operations",
    "persistence_behavior",
    "unrestricted_browser",
    "unrestricted_shell",
    "data_exfiltration",
    "brute_force",
    "credential_stuffing",
]

ALLOWED_SOURCES = [
    "public_search",
    "public_webpage",
    "public_api",
    "public_archive",
    "public_registry",
    "public_social_profile",
    "public_dns_record",
    "public_certificate_transparency",
    "public_whois_record",
]

MAX_CONCURRENT_REQUESTS = 5
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_SEARCH_RESULTS = 10
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2
USE_CONCURRENT = True

CONFIDENCE_THRESHOLDS = {
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
    "minimal": 0.0,
}


def get_env(key: str, default: str = "") -> str:
    """Retrieve an environment variable with fallback."""
    return os.environ.get(key, default)


def get_provider_config() -> dict:
    """Return provider configuration from environment."""
    return {
        "groq": {
            "api_key": get_env("GROQ_API_KEY"),
            "base_url": get_env("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
        },
        "openrouter": {
            "api_key": get_env("OPENROUTER_API_KEY"),
            "base_url": get_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        },
    }


def get_retrieval_config() -> dict:
    """Return web retrieval provider configuration."""
    return {
        "scraperapi_key": get_env("SCRAPERAPI_KEY"),
        "browserless_token": get_env("BROWSERLESS_TOKEN"),
        "search_api_key": get_env("SEARCH_API_KEY"),
    }
