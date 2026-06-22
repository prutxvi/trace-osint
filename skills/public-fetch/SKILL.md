# Skill: Public Fetch

## Purpose
Retrieve content from publicly accessible web pages using read-only HTTP methods.

## Methods
- Direct HTTP GET with timeout and retry
- ScraperAPI integration for JavaScript-rendered pages
- Browserless integration for headless page rendering
- Content extraction and normalization

## Supported Operations
- **Page fetch**: Retrieve full HTML content
- **Content extraction**: Parse readable text from HTML
- **Metadata extraction**: Extract meta tags, Open Graph, JSON-LD
- **Header inspection**: Check HTTP headers and status codes

## Constraints
- No form submissions
- No authentication headers
- No cookie manipulation
- No redirect following beyond 3 hops
- Maximum 30 second timeout per request
- Maximum 5 concurrent requests

## Output
Returns Finding objects with page content, metadata, and confidence scores.
