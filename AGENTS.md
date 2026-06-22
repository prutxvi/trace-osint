# TRACE OSINT Copilot - Agent Definitions

This document defines the specialized agents in the TRACE multi-agent OSINT system.

## Agent Architecture

```
analyst@trace:~$ trace new -c "target@email.com" "target_username"
                    |
                    v
              +-----------+
              |  PLANNER  |  Creates investigation plan from clues
              +-----+-----+
                    |
                    v
              +-----------+
              | COLLECTOR |  Executes public-source data retrieval
              +-----+-----+
                    |
                    v
              +-----------+
              |  RESOLVER |  Normalizes and deduplicates entities
              +-----+-----+
                    |
                    v
              +-----------+
              |  ANALYST  |  Interprets findings, identifies gaps
              +-----+-----+
                    |
                    v
              +-----------+
              |  REPORTER |  Generates final markdown/JSON reports
              +-----+-----+
                    |
                    v
              +-----------+
              |  AUDITOR  |  Records actions, enforces policy
              +-----------+
```

## Agent Definitions

### Planner
- **File**: `.opencode/agents/planner.md`
- **Role**: Transforms clues into step-by-step investigation plans
- **Input**: Case clues and objectives
- **Output**: InvestigationPlan with ordered steps

### Collector
- **File**: `.opencode/agents/collector.md`
- **Role**: Executes approved public-source data retrieval
- **Input**: Plan steps with action specifications
- **Output**: Finding objects with source metadata

### Resolver
- **File**: `.opencode/agents/resolver.md`
- **Role**: Normalizes entities and merges duplicates
- **Input**: Raw findings from collection
- **Output**: Entity objects with canonical values

### Analyst
- **File**: `.opencode/agents/analyst.md`
- **Role**: Interprets results and identifies intelligence gaps
- **Input**: Findings and resolved entities
- **Output**: Analysis with key findings, gaps, and next steps

### Reporter
- **File**: `.opencode/agents/reporter.md`
- **Role**: Generates final investigation reports
- **Input**: Complete case data
- **Output**: Markdown and JSON report files

### Auditor
- **File**: `.opencode/agents/auditor.md`
- **Role**: Records every action and enforces policy compliance
- **Input**: All workflow events
- **Output**: Audit trail with trace IDs

## Policy Enforcement

All agents enforce READ_ONLY policy:
- No private account access
- No credential usage
- No form submissions
- No authentication attempts
- No blocked action categories

## Communication Pattern

Agents communicate through the shared Case object:
1. Planner writes the plan
2. Collector executes and writes findings
3. Resolver normalizes and writes entities
4. Analyst interprets and annotates
5. Reporter generates outputs
6. Auditor records everything
