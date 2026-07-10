from __future__ import annotations
"""TRACE OSINT Copilot - Audit Logger Module"""

from datetime import datetime, timezone

from src.models import AuditEvent, Case


class AuditLogger:
    """Maintains a complete audit trail for an investigation."""

    def __init__(self, case_id: str, trace_id: str = ""):
        self.case_id = case_id
        self.trace_id = trace_id or f"{case_id}-trace"
        self._sequence = 0
        self.events: list[AuditEvent] = []

    def _next_trace(self, phase: str) -> str:
        self._sequence += 1
        return f"{self.case_id}-{phase}-{self._sequence:03d}"

    def log(
        self,
        phase: str,
        agent: str,
        action: str,
        detail: str = "",
        status: str = "ok",
        source_ref: str = "",
    ) -> AuditEvent:
        """Log an audit event."""
        trace_id = self._next_trace(phase)
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            trace_id=trace_id,
            phase=phase,
            agent=agent,
            action=action,
            detail=detail,
            status=status,
            source_ref=source_ref,
        )
        self.events.append(event)
        return event

    def log_tool(self, phase: str, agent: str, tool_name: str, detail: str = "") -> AuditEvent:
        """Log a tool invocation."""
        return self.log(phase, agent, f"tool:{tool_name}", detail)

    def log_search(self, phase: str, agent: str, query: str) -> AuditEvent:
        """Log a search operation."""
        return self.log(phase, agent, "search", f"query={query}")

    def log_fetch(self, phase: str, agent: str, url: str) -> AuditEvent:
        """Log a URL fetch operation."""
        return self.log(phase, agent, "fetch", f"url={url}", source_ref=url)

    def log_error(self, phase: str, agent: str, action: str, error: str) -> AuditEvent:
        """Log an error event."""
        return self.log(phase, agent, action, error, status="error")

    def log_blocked(self, phase: str, agent: str, action: str, reason: str) -> AuditEvent:
        """Log a blocked action."""
        return self.log(phase, agent, action, reason, status="blocked")

    def get_events_for_case(self) -> list[AuditEvent]:
        """Return all events for this case."""
        return list(self.events)

    def merge_into_case(self, case: Case) -> Case:
        """Merge audit events into a case object."""
        case.audit_log.extend(self.events)
        return case

    def summary(self) -> dict:
        """Return an audit summary."""
        total = len(self.events)
        ok = sum(1 for e in self.events if e.status == "ok")
        errors = sum(1 for e in self.events if e.status == "error")
        blocked = sum(1 for e in self.events if e.status == "blocked")
        return {
            "case_id": self.case_id,
            "total_events": total,
            "ok": ok,
            "errors": errors,
            "blocked": blocked,
            "agents_used": list(set(e.agent for e in self.events)),
            "phases_covered": list(set(e.phase for e in self.events)),
        }
