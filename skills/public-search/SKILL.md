# Skill: Public Search

## Purpose
Perform read-only searches against public search engines and indexed web content.

## Methods
- Structured search queries with entity-aware formatting
- Multi-query strategies for comprehensive coverage
- Result ranking and relevance scoring

## Supported Query Types
- **Person search**: `"John Smith" profile OR account`
- **Username search**: `"username" site:github.com OR site:twitter.com`
- **Email search**: `"user@domain.com" contact OR about`
- **Domain search**: `site:example.com` or `"example.com" WHOIS`
- **URL search**: `inurl:specific-path`

## Rate Limits
- Maximum 10 queries per minute
- Minimum 1 second between requests
- Backoff on 429 responses

## Output
Returns Finding objects with source metadata, confidence scores, and extracted entities.

## Constraints
- Public search results only
- No authenticated searches
- No private search APIs
- No automated clicking or interaction
