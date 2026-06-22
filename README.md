<img width="658" height="904" alt="Screenshot 2026-06-23 at 12 31 27 AM" src="https://github.com/user-attachments/assets/393d8324-10ac-4104-8c74-080fa4f1d625" />
<img width="1415" height="704" alt="Screenshot 2026-06-22 at 11 21 53 PM" src="https://github.com/user-attachments/assets/2e8b77cf-8993-4e18-9b11-e900a8d8684a" />



<div align="center">

# TRACE // OSINT Copilot

**Terminal-native multi-agent OSINT copilot for lawful public-source intelligence workflows.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rich](https://img.shields.io/badge/Terminal-Rich-cyan.svg)](https://github.com/Textualize/rich)
[![Pydantic](https://img.shields.io/badge/Schemas-Pydantic-red.svg)](https://pydantic.dev)

</div>

---

## What is TRACE?

TRACE is a premium, cyber-operator-grade investigation console that runs entirely in your terminal. It uses a **multi-agent architecture** to collect, resolve, analyze, and report on public-source intelligence -- all within strict read-only, lawful boundaries.

**Type your clues. Watch it work. Get a dossier.**

TRACE takes a single clue -- an email, username, domain, phone number, or GitHub/LinkedIn URL -- and automatically gathers all publicly available intelligence. It produces structured PDF, Markdown, JSON, and STIX reports with full audit trails.

---

## Safety Model

TRACE operates under strict constraints:

| Policy | Status |
|--------|--------|
| **Default Mode** | `READ_ONLY` |
| **Private Access** | BLOCKED |
| **Credential Use** | BLOCKED |
| **Phishing / Malware** | BLOCKED |
| **Breach Content** | BLOCKED (high-level presence only) |
| **Exploitation** | BLOCKED |

All data comes from public sources. Every action is logged with trace IDs. Breach intelligence shows presence only (e.g., "this email appears in breach index X") -- never passwords, tokens, or leaked content.

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
pip install -r requirements.txt
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
| `GROQ_API_KEY` | LLM analysis (optional) | [console.groq.com](https://console.groq.com/) |
| `SHODAN_API_KEY` | Infrastructure scanning (optional) | [shodan.io](https://shodan.io/) |

### Run

```bash
python -m src.cli
```

---

## CLI Commands

TRACE uses Typer for a professional CLI experience.

### Full Investigation

```bash
# Multi-clue investigation
python -m src.cli case target@email.com github.com/target linkedin.com/in/target

# Email-first investigation
python -m src.cli id --email target@gmail.com

# Phone-first investigation
python -m src.cli id --phone +919876543210

# Self-OSINT
python -m src.cli self --email me@gmail.com --github myhandle
```

### Case Management

```bash
# Add a clue to existing case
python -m src.cli add CASE-XXXX new_clue@gmail.com

# Re-run investigation
python -m src.cli rerun CASE-XXXX

# List all cases
python -m src.cli list-cases

# Check case status
python -m src.cli status CASE-XXXX
```

### Interactive Mode

```bash
python -m src.cli
trace > target@gmail.com github.com/target
trace > run
trace > profile
trace > timeline
trace > story
```

---

## Input Formats

TRACE accepts these clue types:

| Type | Example | Modules Unlocked |
|------|---------|------------------|
| Email | `target@gmail.com` | email_intel, breach_check, people_search, web_search |
| GitHub | `github.com/user` | github_profile, commit_unmasker, secret_hunter |
| LinkedIn | `linkedin.com/in/user` | linkedin_profile, profile_page |
| Domain | `example.com` | domain_intel, shodan, tech_fingerprint, subdomain_takeover |
| Username | `johndoe123` | username_check (400+), github_intel, wikidata |
| Phone | `+919876543210` | india_intel, people_search |
| IP | `8.8.8.8` | shodan_ip, ip_intel |

**More clue types = more modules = richer dossier.**

---

## Capabilities

- **25+ source modules** -- email, domain, GitHub, LinkedIn, Shodan, OpenCorporates, Wikidata, India Kanoon, breach databases, and more
- **400+ platform username check** -- parallel checks across Twitter, Instagram, Reddit, TikTok, Steam, etc.
- **Commit author unmasking** -- extract real names from public Git history
- **Secret leak scanning** -- GitHub code, Gists, Pastebin for AWS keys, tokens, passwords
- **Tech stack fingerprinting** -- detect 30+ technologies (WordPress, React, Cloudflare, etc.)
- **Subdomain takeover detection** -- find dangling CNAMEs pointing to vulnerable services
- **Identity collapse** -- unified digital twin from fragmented findings
- **AI pivot engine** -- Groq-powered next-step suggestions
- **Story card synthesis** -- plain-language dossier narrative
- **Interactive graph** -- NetworkX + Pyvis HTML visualization
- **Concurrent collection** -- ThreadPoolExecutor with configurable parallelism
- **Plugin system** -- extend with custom collectors and analyzers

---

## Output Formats

Each investigation generates:

| File | Format | Description |
|------|--------|-------------|
| `report.pdf` | PDF | Styled investigation dossier with avatar |
| `report.md` | Markdown | 14-section person-first report |
| `report.json` | JSON | Structured evidence file |
| `stix.json` | STIX 2.1 | Interoperable intelligence bundle |
| `investigation_graph.html` | HTML | Interactive network visualization |
| `audit_log.txt` | Text | Complete audit trail with trace IDs |
| `run_log.txt` | Text | Execution log with tool activity |

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
  | COLLECTOR |  Executes public-source data retrieval (concurrent)
  +-----+-----+
        |
        v
  +-----------+
  |  RESOLVER |  Normalizes entities, merges duplicates
  +-----+-----+
        |
        v
  +-----------+
  |  ANALYST  |  Identity collapse, AI pivots, risk scoring
  +-----+-----+
        |
        v
  +-----------+
  |  REPORTER |  PDF + Markdown + JSON + STIX + Graph
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
│   ├── cli/              # Typer CLI application
│   │   ├── app.py        # Main CLI entry point
│   │   └── commands/     # Command implementations
│   ├── config/           # Configuration & policy
│   ├── clues/            # Clue parsing & classification
│   ├── collectors/       # 25+ data collection modules
│   ├── correlation/      # Entity resolution & cross-linking
│   ├── analysis/         # Identity collapse, AI pivots, scoring
│   ├── reporting/        # PDF, Markdown, JSON, STIX, Graph
│   ├── audit/            # Audit logging with trace IDs
│   ├── models/           # Pydantic data schemas
│   └── plugins/          # Plugin system
├── plugins/              # User plugins directory
├── tests/                # Test suite (pytest)
├── cases/                # Case storage (gitignored)
├── requirements.txt      # Python dependencies
└── .env.example          # Environment template
```

---

## Testing

```bash
cd trace-osint
source venv/bin/activate
pytest tests/ -v
```

### Test Coverage

- Clue parser and case mode detection
- Entity correlation and cross-linking
- Identity collapse engine
- Exposure scoring logic

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture details, how to add new source modules, and how to run tests.

---

## License

MIT License -- see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for lawful, ethical public-source intelligence gathering.**

</div>
