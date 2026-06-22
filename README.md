<div align="center">

# TRACE // OSINT Copilot

**Terminal-native multi-agent OSINT copilot for lawful public-source intelligence workflows.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rich](https://img.shields.io/badge/Terminal-Rich-cyan.svg)](https://github.com/Textualize/rich)
[![Pydantic](https://img.shields.io/badge/Schemas-Pydantic-red.svg)](https://pydantic.dev)

```
 _____ ____  ____      ___           _
|_   _|  _ \|  _ \    / _ \ _ __ ___| |_
  | | | |_) | |_) |  / /_)/ '__/ _ \ __|
  | | |  _ <|  __/  / ___/| | |  __/ |_
  |_| |_| \_\_|    /_/    |_|  \___|\__|
```

</div>

---

## What is TRACE?

TRACE is a premium, cyber-operator-grade investigation console that runs entirely in your terminal. It uses a **multi-agent architecture** to collect, resolve, analyze, and report on public-source intelligence -- all within strict read-only, lawful boundaries.

**Type your clues. Watch it work. Get a report.**

---

## Features

- **Chat-based interface** -- just type what you know, TRACE figures out the rest
- **Multi-agent pipeline** -- Planner, Collector, Resolver, Analyst, Reporter, Auditor
- **Live terminal UI** -- Rich panels, progress indicators, color-coded output
- **Natural language parsing** -- emails, usernames, domains, URLs, phone numbers auto-detected
- **Public-source only** -- hardcoded read-only policy, audit trail, blocked action enforcement
- **Dual report output** -- Markdown + JSON structured evidence files
- **ScraperAPI + Browserless integration** -- JavaScript-rendered page support
- **Case management** -- create, list, inspect, replay past investigations
- **Full audit trail** -- every action logged with trace IDs for compliance

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip

### Install

```bash
git clone https://github.com/prutxvi/trace-osint.git
cd trace-osint
python -m venv venv
source venv/bin/activate
pip install typer rich pydantic
```

### Configure

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

| Key | Purpose | Get it |
|-----|---------|--------|
| `SCRAPERAPI_KEY` | Web page fetching | [scraperapi.com](https://www.scraperapi.com/) |
| `BROWSERLESS_TOKEN` | Headless browser | [browserless.io](https://www.browserless.io/) |
| `SEARCH_API_KEY` | Search queries | Your search provider |
| `GROQ_API_KEY` | LLM (optional) | [console.groq.com](https://console.groq.com/) |
| `OPENROUTER_API_KEY` | LLM (optional) | [openrouter.ai](https://openrouter.ai/) |

### Run

```bash
python -m src.cli
```

---

## Usage

### Interactive Chat

```
trace > I have an email target@startup.io and their website is startup.io

  #   Detected            Type
  1   target@startup.io   email
  2   startup.io          domain

+ New case created: CASE-ED55C365

trace (CASE-ED55C365) > run

> Phase: PLANNING    Generating investigation plan...
> Phase: COLLECTING  Executing collection plan...
  + search_email   -- 20 finding(s)
  + search_domain  -- 16 finding(s)
> Phase: RESOLVING   Resolving and normalizing entities...
> Phase: ANALYZING   Analyzing findings...
> Phase: REPORTING   Generating reports...

  Findings Collected    36
  Entities Resolved     12

Reports saved to cases/CASE-ED55C365/reports/
```

### Commands

| Command | Description |
|---------|-------------|
| `help` | Show usage guide |
| `status` | Current case status |
| `list` | List all past cases |
| `report` | Show final markdown report |
| `cases` | Switch to a past case |
| `clear` | Clear screen |
| `exit` | Quit TRACE |

---

## Architecture

```
User Input (clues)
       |
       v
  +-----------+
  |  PLANNER  |  Creates step-by-step investigation plan
  +-----+-----+
        |
        v
  +-----------+
  | COLLECTOR |  Executes public-source data retrieval
  +-----+-----+
        |
        v
  +-----------+
  |  RESOLVER |  Normalizes entities, merges duplicates
  +-----+-----+
        |
        v
  +-----------+
  |  ANALYST  |  Interprets findings, identifies gaps
  +-----+-----+
        |
        v
  +-----------+
  |  REPORTER |  Generates markdown + JSON reports
  +-----+-----+
        |
        v
  +-----------+
  |  AUDITOR  |  Records every action with trace IDs
  +-----------+
```

### Project Structure

```
trace-osint/
├── src/
│   ├── cli.py              # Interactive chat CLI
│   ├── workflow.py         # Investigation engine
│   ├── config.py           # Configuration & policy
│   ├── models.py           # Pydantic schemas
│   ├── theme.py            # Terminal theme
│   ├── case_store.py       # Case persistence
│   ├── ui_helpers.py       # Rich UI rendering
│   ├── sources/            # Data collection modules
│   ├── parsers/            # Content parsing
│   ├── scoring/            # Confidence & exposure
│   ├── reporting/          # Report generation
│   └── audit/              # Audit logging
├── .opencode/agents/       # Agent definitions
├── skills/                 # Skill documentation
├── cases/                  # Case storage (gitignored)
├── .env.example            # Environment template
└── opencode.json           # OpenCode config
```

---

## Safety & Policy

TRACE enforces strict boundaries:

| Policy | Status |
|--------|--------|
| **Default Mode** | `READ_ONLY` |
| **Private Access** | BLOCKED |
| **Credential Use** | BLOCKED |
| **Phishing / Malware** | BLOCKED |
| **Breach Databases** | BLOCKED |
| **Exploitation** | BLOCKED |

Every action is logged. Every case has a full audit trail. Policy mode is always visible in the terminal header.

---

## Report Outputs

Each investigation generates:

| File | Format | Description |
|------|--------|-------------|
| `report.md` | Markdown | Human-readable investigation report |
| `report.json` | JSON | Structured evidence file |
| `run_log.txt` | Text | Execution log with tool activity |
| `audit_log.txt` | Text | Complete audit trail with trace IDs |

---

## License

MIT License -- see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for lawful, ethical public-source intelligence gathering.**

</div>
