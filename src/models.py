"""TRACE OSINT Copilot - Pydantic Data Models"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    PERSON = "person"
    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    URL = "url"
    PHONE = "phone"
    ORGANIZATION = "organization"
    IP_ADDRESS = "ip_address"
    CRYPTO_ADDRESS = "crypto_address"
    UNKNOWN = "unknown"


class Confidence(BaseModel):
    score: float = Field(ge=0.0, le=1.0, default=0.0)
    level: str = "minimal"
    reasoning: str = ""

    def compute_level(self) -> str:
        if self.score >= 0.8:
            self.level = "high"
        elif self.score >= 0.5:
            self.level = "medium"
        elif self.score >= 0.3:
            self.level = "low"
        else:
            self.level = "minimal"
        return self.level


class Source(BaseModel):
    url: str = ""
    title: str = ""
    retrieved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_type: str = "public_search"
    reliability: float = Field(ge=0.0, le=1.0, default=0.5)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    entity_type: EntityType = EntityType.UNKNOWN
    entity_value: str = ""
    label: str = ""
    summary: str = ""
    details: dict = Field(default_factory=dict)
    source: Source = Field(default_factory=Source)
    confidence: Confidence = Field(default_factory=Confidence)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Entity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    type: EntityType = EntityType.UNKNOWN
    value: str = ""
    aliases: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default_factory=Confidence)
    finding_ids: list[str] = Field(default_factory=list)


class PlanStep(BaseModel):
    step_id: int = 0
    action: str = ""
    description: str = ""
    source: str = ""
    risk_level: str = "low"
    status: str = "pending"
    result: str = ""


class InvestigationPlan(BaseModel):
    case_id: str = ""
    objective: str = ""
    steps: list[PlanStep] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str = ""
    phase: str = ""
    agent: str = ""
    action: str = ""
    detail: str = ""
    status: str = "ok"
    source_ref: str = ""


class Case(BaseModel):
    case_id: str = Field(default_factory=lambda: f"CASE-{uuid4().hex[:8].upper()}")
    name: str = ""
    clues: list[str] = Field(default_factory=list)
    policy_mode: str = "READ_ONLY"
    phase: str = "initialized"
    plan: Optional[InvestigationPlan] = None
    findings: list[Finding] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    audit_log: list[AuditEvent] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "active"
