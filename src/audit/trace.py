"""TRACE OSINT Copilot - Trace Correlation Module"""

from src.models import AuditEvent, Case


def get_trace_chain(events: list[AuditEvent], trace_id: str) -> list[AuditEvent]:
    """Get all events sharing a trace ID prefix."""
    prefix = "-".join(trace_id.split("-")[:-1])
    return [e for e in events if e.trace_id.startswith(prefix)]


def get_phase_events(events: list[AuditEvent], phase: str) -> list[AuditEvent]:
    """Get all events for a specific phase."""
    return [e for e in events if e.phase == phase]


def get_agent_events(events: list[AuditEvent], agent: str) -> list[AuditEvent]:
    """Get all events for a specific agent."""
    return [e for e in events if e.agent == agent]


def get_failed_events(events: list[AuditEvent]) -> list[AuditEvent]:
    """Get all events that resulted in errors or blocks."""
    return [e for e in events if e.status in ("error", "blocked")]


def get_source_refs(events: list[AuditEvent]) -> list[str]:
    """Extract all unique source references from events."""
    refs = set()
    for e in events:
        if e.source_ref:
            refs.add(e.source_ref)
    return sorted(refs)


def build_timeline(events: list[AuditEvent]) -> list[dict]:
    """Build a chronological timeline of investigation events."""
    timeline = []
    for e in sorted(events, key=lambda x: x.timestamp):
        timeline.append({
            "time": e.timestamp,
            "trace": e.trace_id,
            "phase": e.phase,
            "agent": e.agent,
            "action": e.action,
            "status": e.status,
        })
    return timeline


def trace_integrity_check(events: list[AuditEvent]) -> dict:
    """Verify audit trail integrity."""
    issues = []
    for i, event in enumerate(events):
        if not event.timestamp:
            issues.append(f"Event {i}: missing timestamp")
        if not event.trace_id:
            issues.append(f"Event {i}: missing trace_id")
        if not event.phase:
            issues.append(f"Event {i}: missing phase")
        if not event.agent:
            issues.append(f"Event {i}: missing agent")

    return {
        "total_events": len(events),
        "issues": issues,
        "valid": len(issues) == 0,
    }
