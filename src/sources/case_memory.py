from __future__ import annotations
"""TRACE OSINT - Case Memory & Learning System

Tracks patterns across investigations to improve future results.
Uses SQLite for persistent storage.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.config import PROJECT_ROOT


DB_PATH = PROJECT_ROOT / "cases" / "trace_memory.db"


def _get_db() -> sqlite3.Connection:
    """Get or create the memory database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            clues TEXT,
            findings_count INTEGER,
            entities_count INTEGER,
            risk_score REAL,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            entity_type TEXT,
            entity_value TEXT,
            source_type TEXT,
            confidence_level TEXT,
            confidence_score REAL,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT,
            pattern_value TEXT,
            frequency INTEGER DEFAULT 1,
            last_seen TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS source_effectiveness (
            source_type TEXT PRIMARY KEY,
            total_queries INTEGER DEFAULT 0,
            successful_queries INTEGER DEFAULT 0,
            avg_confidence REAL DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def save_case_memory(case_id: str, clues: list[str], findings_count: int,
                     entities_count: int, risk_score: float):
    """Save case metadata to memory."""
    conn = _get_db()
    conn.execute(
        "INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, json.dumps(clues), findings_count, entities_count,
         risk_score, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def save_finding_memory(case_id: str, finding):
    """Save a finding to memory for pattern analysis."""
    conn = _get_db()
    conn.execute(
        "INSERT INTO findings (case_id, entity_type, entity_value, source_type, "
        "confidence_level, confidence_score, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, finding.entity_type.value, finding.entity_value,
         finding.source.source_type, finding.confidence.level,
         finding.confidence.score, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def update_pattern(pattern_type: str, pattern_value: str):
    """Update pattern frequency."""
    conn = _get_db()
    existing = conn.execute(
        "SELECT id, frequency FROM patterns WHERE pattern_type = ? AND pattern_value = ?",
        (pattern_type, pattern_value)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE patterns SET frequency = frequency + 1, last_seen = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), existing[0])
        )
    else:
        conn.execute(
            "INSERT INTO patterns (pattern_type, pattern_value, last_seen) VALUES (?, ?, ?)",
            (pattern_type, pattern_value, datetime.now(timezone.utc).isoformat())
        )
    conn.commit()
    conn.close()


def update_source_effectiveness(source_type: str, success: bool, confidence: float):
    """Track which sources give the best results."""
    conn = _get_db()
    existing = conn.execute(
        "SELECT * FROM source_effectiveness WHERE source_type = ?",
        (source_type,)
    ).fetchone()

    if existing:
        total = existing[1] + 1
        successful = existing[2] + (1 if success else 0)
        avg_conf = ((existing[3] * existing[1]) + confidence) / total
        conn.execute(
            "UPDATE source_effectiveness SET total_queries = ?, successful_queries = ?, avg_confidence = ? WHERE source_type = ?",
            (total, successful, avg_conf, source_type)
        )
    else:
        conn.execute(
            "INSERT INTO source_effectiveness VALUES (?, ?, ?, ?)",
            (source_type, 1, 1 if success else 0, confidence)
        )
    conn.commit()
    conn.close()


def get_best_sources(limit: int = 10) -> list[dict]:
    """Get the most effective data sources."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT source_type, total_queries, successful_queries, avg_confidence "
        "FROM source_effectiveness ORDER BY avg_confidence DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [
        {
            "source": r[0],
            "total_queries": r[1],
            "successful_queries": r[2],
            "success_rate": r[2] / max(r[1], 1),
            "avg_confidence": r[3],
        }
        for r in rows
    ]


def get_frequent_patterns(pattern_type: str = "", limit: int = 20) -> list[dict]:
    """Get frequently seen patterns."""
    conn = _get_db()
    if pattern_type:
        rows = conn.execute(
            "SELECT pattern_type, pattern_value, frequency FROM patterns "
            "WHERE pattern_type = ? ORDER BY frequency DESC LIMIT ?",
            (pattern_type, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT pattern_type, pattern_value, frequency FROM patterns "
            "ORDER BY frequency DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [{"type": r[0], "value": r[1], "frequency": r[2]} for r in rows]


def get_case_stats() -> dict:
    """Get overall investigation statistics."""
    conn = _get_db()
    total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    avg_findings = conn.execute("SELECT AVG(findings_count) FROM cases").fetchone()[0] or 0
    avg_risk = conn.execute("SELECT AVG(risk_score) FROM cases").fetchone()[0] or 0
    conn.close()

    return {
        "total_cases": total_cases,
        "total_findings": total_findings,
        "avg_findings_per_case": round(avg_findings, 1),
        "avg_risk_score": round(avg_risk, 3),
    }
