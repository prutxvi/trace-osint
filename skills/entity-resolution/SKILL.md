# Skill: Entity Resolution

## Purpose
Normalize, deduplicate, and merge entity representations across findings.

## Supported Entity Types
- **Email**: Lowercase, validate format, strip whitespace
- **Username**: Lowercase, remove prefixes, normalize
- **URL**: Normalize scheme, strip tracking params, canonical form
- **Domain**: Lowercase, strip www, validate TLD
- **Phone**: Strip non-digits, normalize format
- **Name**: Case-fold, normalize whitespace, handle transliterations

## Resolution Process
1. Extract all entity mentions from findings
2. Normalize each entity to canonical form
3. Group entities by type
4. Merge likely duplicates using fuzzy matching
5. Compute confidence based on corroboration count
6. Assign canonical values with alias tracking

## Confidence Scoring
- **High (0.8+)**: 3+ independent sources
- **Medium (0.5-0.79)**: 2 sources or 1 highly reliable
- **Low (0.3-0.49)**: Single source, partial match
- **Minimal (0.0-0.29)**: Inferred or ambiguous
