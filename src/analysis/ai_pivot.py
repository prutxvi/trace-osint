from __future__ import annotations
"""TRACE OSINT - AI Pivot Engine

Uses Groq/LLM to make intelligent decisions about next investigation steps.
Analyzes findings and suggests pivots like a real analyst would.
"""

import json
import urllib.request
from typing import Optional

from src.config import get_env
from src.models import Finding, Entity, Case


def _call_groq(prompt: str, system: str = "") -> str:
    """Call Groq API for AI reasoning."""
    api_key = get_env("GROQ_API_KEY")
    if not api_key:
        return ""

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1000,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception:
        return ""


def analyze_findings(case: Case) -> dict:
    """Use AI to analyze findings and suggest next steps."""
    findings_summary = []
    for f in case.findings[:30]:
        findings_summary.append({
            "type": f.entity_type.value,
            "value": f.entity_value[:50],
            "label": f.label[:50],
            "confidence": f.confidence.level,
            "source": f.source.source_type,
        })

    entities_summary = []
    for e in case.entities[:20]:
        entities_summary.append({
            "type": e.type.value,
            "value": e.value[:50],
            "confidence": e.confidence.level,
        })

    prompt = f"""Analyze these OSINT findings and provide:
1. Key insights about the target
2. Patterns or connections found
3. Gaps in the investigation
4. Recommended next steps (only legal, public-source methods)
5. Risk assessment

Findings: {json.dumps(findings_summary[:20])}
Entities: {json.dumps(entities_summary[:10])}
Clues: {case.clues}

Provide analysis as JSON with keys: insights, patterns, gaps, next_steps, risk_assessment"""

    system = """You are an expert OSINT analyst. Analyze the findings and provide actionable intelligence.
Only recommend legal, public-source investigation methods.
Be specific about what each next step would reveal.
Format your response as valid JSON."""

    response = _call_groq(prompt, system)

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return {
            "insights": [response[:500]] if response else ["AI analysis unavailable"],
            "patterns": [],
            "gaps": ["AI analysis unavailable"],
            "next_steps": [],
            "risk_assessment": "Unable to determine",
        }


def suggest_pivots(findings: list[Finding], entities: list[Entity]) -> list[dict]:
    """Suggest investigation pivots based on current findings."""
    pivot_suggestions = []

    for finding in findings:
        if finding.entity_type.value == "email":
            domain = finding.entity_value.split("@")[-1]
            pivot_suggestions.append({
                "from": finding.entity_value,
                "to": domain,
                "reason": f"Email domain '{domain}' may reveal organization and infrastructure",
                "action": "domain_intel",
            })

        if finding.entity_type.value == "domain":
            details = finding.details or {}
            if details.get("registrant"):
                pivot_suggestions.append({
                    "from": finding.entity_value,
                    "to": details["registrant"],
                    "reason": f"Domain registrant '{details['registrant']}' may be linked person",
                    "action": "search_person",
                })

        if finding.entity_type.value == "username":
            pivot_suggestions.append({
                "from": finding.entity_value,
                "to": f"{finding.entity_value}@gmail.com",
                "reason": "Common email pattern for this username",
                "action": "email_intel",
            })

    seen = set()
    unique_pivots = []
    for p in pivot_suggestions:
        key = f"{p['from']}->{p['to']}"
        if key not in seen:
            seen.add(key)
            unique_pivots.append(p)

    return unique_pivots[:10]


def generate_ai_summary(case: Case) -> str:
    """Generate a natural language summary of the investigation."""
    prompt = f"""Write a brief intelligence summary for this OSINT investigation:
Case: {case.case_id}
Clues investigated: {', '.join(case.clues)}
Total findings: {len(case.findings)}
Entities resolved: {len(case.entities)}

Top findings:
"""
    for f in case.findings[:10]:
        prompt += f"- [{f.confidence.level}] {f.label[:60]}\n"

    prompt += "\nWrite a 2-3 paragraph executive summary suitable for a briefing."

    system = "You are an intelligence analyst writing a brief executive summary. Be concise and factual."

    response = _call_groq(prompt, system)
    return response or f"Investigation of {case.clues} yielded {len(case.findings)} findings and {len(case.entities)} entities."
