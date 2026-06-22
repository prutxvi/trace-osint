# Contributing to TRACE

Thank you for your interest in contributing to TRACE OSINT Copilot.

## Architecture

TRACE follows a modular architecture with clear separation of concerns:

```
src/
├── cli/              # User interface (Typer commands)
├── config/           # Settings, policy, environment
├── clues/            # Input parsing and classification
├── collectors/       # Data collection modules (one per source)
├── correlation/      # Entity resolution and cross-linking
├── analysis/         # Identity collapse, AI pivots, scoring
├── reporting/        # Output generation (PDF, MD, JSON, STIX, Graph)
├── audit/            # Action logging with trace IDs
├── models/           # Pydantic data schemas
└── plugins/          # Extensible plugin system
```

## Adding a New Source Module

1. Create a new file in `src/collectors/` (e.g., `new_source.py`)

2. Implement the collector function:

```python
"""TRACE OSINT - New Source Collector."""

from src.models import Finding, EntityType, Confidence, Source


def get_new_source_intelligence(query: str) -> list[Finding]:
    """Gather intelligence from New Source.

    Args:
        query: The search query (email, username, domain, etc.)

    Returns:
        List of Finding objects with collected intelligence.
    """
    findings = []

    # Your collection logic here
    # ...

    finding = Finding(
        entity_type=EntityType.PERSON,
        entity_value=query,
        label=f"New Source: {query}",
        summary="Description of what was found",
        details={"key": "value"},
        source=Source(
            url="https://newsource.com",
            title="New Source",
            source_type="public_api",
            reliability=0.8,
        ),
        confidence=Confidence(score=0.8, reasoning="Source reliability assessment"),
    )
    finding.confidence.compute_level()
    findings.append(finding)

    return findings
```

3. Register in `src/collectors/__init__.py`:

```python
from src.collectors.new_source import get_new_source_intelligence
```

4. Add to `src/workflow.py`:

```python
from src.collectors.new_source import get_new_source_intelligence

# In _execute_step():
elif step.action == "new_source":
    return get_new_source_intelligence(clue)
```

5. Add plan generation in `_generate_plan()`:

```python
if entity_type == "new_trigger":
    step_id += 1
    steps.append(PlanStep(
        step_id=step_id, action="new_source",
        description=f"New source lookup: {clue}",
        source="new_source", risk_level="low",
    ))
```

## Adding a Plugin

1. Create a file in `plugins/` (e.g., `my_plugin.py`)

2. Implement the plugin:

```python
from src.plugins.base import BasePlugin
from src.models import Case, Finding


class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "My custom plugin"
    version = "1.0.0"

    def collect(self, case: Case) -> list[Finding]:
        """Run collection and return findings."""
        return []

    def analyze(self, case: Case):
        """Run analysis phase."""
        return None
```

3. The plugin is auto-discovered on next run.

## Code Style

- Follow PEP 8
- Use type hints for all function signatures
- Add docstrings (Google style) for public functions
- Keep functions focused and small
- Use Pydantic models for data structures

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_clue_parser.py -v

# Run with coverage
pytest tests/ --cov=src
```

## Safety Rules

All contributions must maintain:

- **READ_ONLY mode** -- no private access, no authentication
- **Public sources only** -- no dark web, no dumps, no stolen data
- **Breach intelligence** -- presence only, never content
- **Audit logging** -- every action must be traceable
- **Policy enforcement** -- all collectors must respect BLOCKED_ACTIONS

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Update documentation if needed
6. Submit a pull request

## Questions?

Open an issue at https://github.com/prutxvi/trace-osint/issues
