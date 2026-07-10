from __future__ import annotations
"""TRACE OSINT Copilot - Case Storage & Retrieval"""

import json
from pathlib import Path
from datetime import datetime, timezone

from src.config import CASES_DIR
from src.models import Case


def _case_dir(case_id: str) -> Path:
    d = CASES_DIR / case_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_case(case: Case) -> Path:
    """Persist a case to disk."""
    d = _case_dir(case.case_id)
    case.updated_at = datetime.now(timezone.utc).isoformat()
    path = d / "case.json"
    path.write_text(case.model_dump_json(indent=2))
    return path


def load_case(case_id: str) -> Case | None:
    """Load a case from disk by ID."""
    path = CASES_DIR / case_id / "case.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return Case(**data)


def list_cases() -> list[dict]:
    """List all stored cases with metadata."""
    cases = []
    for d in sorted(CASES_DIR.iterdir()):
        case_file = d / "case.json"
        if case_file.exists():
            data = json.loads(case_file.read_text())
            cases.append({
                "case_id": data.get("case_id", d.name),
                "name": data.get("name", ""),
                "status": data.get("status", ""),
                "phase": data.get("phase", ""),
                "created_at": data.get("created_at", ""),
                "findings_count": len(data.get("findings", [])),
            })
    return cases


def save_report(case_id: str, filename: str, content: str) -> Path:
    """Save a report file to the case output directory."""
    d = _case_dir(case_id) / "reports"
    d.mkdir(exist_ok=True)
    path = d / filename
    path.write_text(content)
    return path


def get_case_reports(case_id: str) -> list[Path]:
    """List all reports for a case."""
    d = _case_dir(case_id) / "reports"
    if not d.exists():
        return []
    return sorted(d.iterdir())
