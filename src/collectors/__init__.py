# -*- coding: utf-8 -*-
from __future__ import annotations
"""TRACE OSINT Copilot - Collectors Package.

Pluggable data collection modules that retrieve intelligence from public sources.
Each collector exposes a get_*_intelligence() function returning list[Finding].
"""

from src.collectors.email import get_email_intelligence
from src.collectors.domain import get_domain_intelligence
from src.collectors.github import get_github_intelligence
from src.collectors.github_profile import get_github_profile_intelligence
from src.collectors.linkedin import get_linkedin_profile_intelligence
from src.collectors.username import check_username_bulk
from src.collectors.ip import get_ip_intelligence
from src.collectors.shodan import get_shodan_intelligence
from src.collectors.breach import get_breach_intelligence
from src.collectors.people import get_truepeoplesearch_intelligence
from src.collectors.court import get_court_intelligence
from src.collectors.india import get_india_intelligence
from src.collectors.wayback import get_wayback_intelligence
from src.collectors.opencorporates import get_opencorporates_intelligence
from src.collectors.wikidata import get_wikidata_intelligence
from src.collectors.secrets import get_secret_leak_intelligence
from src.collectors.tech import get_tech_stack_intelligence
from src.collectors.subdomain import get_subdomain_takeover_intelligence
from src.collectors.commit import get_commit_author_intelligence
from src.collectors.profile import extract_profile_page_intelligence
from src.collectors.search import public_search, search_username, search_email, search_domain
from src.collectors.fetch import fetch_url_as_finding

__all__ = [
    "get_email_intelligence",
    "get_domain_intelligence",
    "get_github_intelligence",
    "get_github_profile_intelligence",
    "get_linkedin_profile_intelligence",
    "check_username_bulk",
    "get_ip_intelligence",
    "get_shodan_intelligence",
    "get_breach_intelligence",
    "get_truepeoplesearch_intelligence",
    "get_court_intelligence",
    "get_india_intelligence",
    "get_wayback_intelligence",
    "get_opencorporates_intelligence",
    "get_wikidata_intelligence",
    "get_secret_leak_intelligence",
    "get_tech_stack_intelligence",
    "get_subdomain_takeover_intelligence",
    "get_commit_author_intelligence",
    "extract_profile_page_intelligence",
    "public_search",
    "search_username",
    "search_email",
    "search_domain",
    "fetch_url_as_finding",
]
