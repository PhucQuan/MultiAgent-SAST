<div align="center">

# 🔒 Aegis-SAST

**AI-Powered Static Application Security Testing Tool**

*Built for penetration testers and security engineers — finds vulnerabilities before attackers do.*

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Languages](https://img.shields.io/badge/Languages-Python%20%7C%20JS%20%7C%20Java%20%7C%20PHP-green)](#language-support)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-red)](https://owasp.org/Top10/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## What is Aegis-SAST?

Aegis-SAST is a **static analysis tool** that scans source code for security vulnerabilities using a two-layer approach:

1. **Layer 1 — Tree-sitter AST Analysis**: Parses source code into an Abstract Syntax Tree and tracks how untrusted user input (sources) flows into dangerous functions (sinks) without being sanitized — this is called **Taint Analysis**.
2. **Layer 2 — Gemini AI Verification**: Each potential finding is verified by Google Gemini to reduce false positives and provide remediation advice.

> This tool is designed to detect real, exploitable vulnerabilities — not just flag dangerous function names.

---

## Architecture

```mermaid
graph TD
    A[Source Files<br/>.py .js .java .php] --> B[Plugin Registry]
    B --> C{Language Plugin}
    C --> D[Tree-sitter AST Parser]
    D --> E[Taint Analysis Engine]

    F[rules/python.yaml<br/>rules/javascript.yaml<br/>rules/java.yaml<br/>rules/php.yaml] --> G[Rule Engine<br/>Sources · Sinks · Sanitizers]
    G --> E

    H[call_graph.py<br/>FunctionIndex + ImportResolver] --> E
    E --> I[Vulnerability Findings]
    I --> J{AI Verification<br/>Gemini API}
    J --> K[JSON Report]
    J --> L[Markdown Report]
```

## Repository Layout

The repository is now organized to separate product code, research assets, and
developer fixtures more clearly:

```text
aegis_sast/        core scanner, plugins, analysis, triage, orchestration, integrations
benchmarks/        baseline comparison plans and evaluation fixtures
datasets/          synthetic or labeled research datasets
docs/thesis/       graduation-thesis and defense documents
examples/          user-facing demo samples
refs/              third-party reference snapshots
scripts/           workflow utilities and future benchmark helpers
skills/            local skill pack for agent-oriented development
test_projects/     quick local scan targets for manual debugging
tests/             unit and regression tests
```

Design direction:

- `aegis_sast/analysis` remains the deterministic core
- `aegis_sast/triage` holds normalized finding and review decisions
- `aegis_sast/orchestration` is reserved for workflow and LangGraph-style state
- `aegis_sast/knowledge` is reserved for YAML knowledge cards and loaders
- `aegis_sast/integrations` contains CI-facing export formats such as SARIF

## Recent Thesis-Scale Progress

The latest thesis-focused work in `docs/thesis/20..31` has already moved the
project beyond a simple AST demo. The main completed areas are:

| Thesis docs | What is implemented now |
|---|---|
| `20` | knowledge cards and a triage engine seed for evidence-aware review |
| `21` | workflow-state orchestration that is ready to map into LangGraph-style nodes |
| `22` | repo intake, language detection, framework hints, and scan-profile routing |
| `23` | Auditor / Skeptic / Judge node contracts plus source-context handling |
| `24` | installation notes and lightweight smoke-test flow for unstable environments |
| `25` | CPython-first environment guidance for Windows and native-package reliability |
| `26` | workflow metadata exported into JSON, Markdown, and SARIF |
| `27` | explicit Python CFG/DFG graph foundation (`python_flow_graph.py`) |
| `28` | taint-kill, dead-path pruning, and basic `try/except/finally` control-flow support |
| `29` | `break` / `continue`, `loop else`, local function summaries, and richer path metadata |
| `30` | `scripts/manual_graph_smoke.py` for graph-core verification without Tree-sitter |
| `31` | synthetic ablation benchmark for Python graph v1.2 with JSON/Markdown outputs |

From an engineering perspective, the repository now has:

- a normalized finding and evidence pipeline for triage/reporting
- staged orchestration nodes that can evolve into a full agent workflow
- enriched SARIF / Markdown / JSON outputs with workflow and graph evidence
- an explicit Python graph-analysis core that is already testable outside the full plugin stack
- a repeatable mini benchmark for graph ablation, not just a benchmark plan on paper

### How Taint Analysis Works

```
Source (untrusted input)
  │
  │  request.args.get('id')          ← HTTP parameter
  ▼
Propagation (variable tracking)
  │
  │  user_id = request.args.get('id')
  │  query   = f"SELECT * FROM users WHERE id={user_id}"
  ▼
Sink (dangerous function)
  │
  │  db.execute(query)               ← SQL Injection!
  ▼
Finding: [CRITICAL] SQL_INJECTION @ app.py:42
```

### Cross-file Tracking (Level-B Inter-procedural)

```
utils.py                         app.py
─────────────────────            ──────────────────────────
def get_command():               from utils import get_command
    cmd = request.args.get('cmd')
    return cmd                   cmd = get_command()  ← Synthetic source
                                 os.system(cmd)       ← SINK detected!
```

---

## Features

### Language Support

| Language | Extensions | Parser |
|---|---|---|
| 🐍 Python | `.py`, `.pyw` | tree-sitter-python |
| 🟨 JavaScript / Node.js | `.js`, `.mjs`, `.cjs` | tree-sitter-javascript |
| ☕ Java | `.java` | tree-sitter-java |
| 🐘 PHP | `.php`, `.phtml` | tree-sitter-php |

### OWASP Top 10 Coverage

| Vulnerability | Python | JavaScript | Java | PHP |
|---|:---:|:---:|:---:|:---:|
| SQL Injection | ✅ | ✅ | ✅ | ✅ |
| Command Injection (RCE) | ✅ | ✅ | ✅ | ✅ |
| Code Injection | ✅ | ✅ | ✅ | ✅ |
| Path Traversal / LFI | ✅ | ✅ | ✅ | ✅ |
| Cross-Site Scripting (XSS) | ✅ | ✅ | ✅ | ✅ |
| Server-Side Request Forgery | ✅ | ✅ | ✅ | ✅ |
| XML External Entity (XXE) | ✅ | — | ✅ | ✅ |
| NoSQL Injection | ✅ | ✅ | — | — |
| Insecure Deserialization | ✅ | ✅ | ✅ | ✅ |
| SSTI | ✅ | — | — | — |
| IDOR | ✅ | — | — | — |
| Mass Assignment | ✅ | — | — | — |
| Open Redirect | ✅ | ✅ | ✅ | — |

### Key Capabilities

| Feature | Details |
|---|---|
| **AST-based analysis** | Uses Tree-sitter for precise, language-aware parsing — not just regex |
| **Taint flow tracking** | Follows data from `source → variable → sink` through assignments and aliasing |
| **Cross-file analysis** | Detects vulnerabilities that span multiple files via import tracking |
| **Sanitizer awareness** | Recognises safe functions (e.g. `parameterized queries`, `htmlspecialchars`) and marks paths as low-risk |
| **AI Verification** | Gemini API verifies each finding to suppress false positives |
| **Reports and CI** | JSON, Markdown, and SARIF export for CI/CD and code scanning workflows |
| **Docker support** | Run without installing anything locally |

---

## Installation

### Option 1: virtualenv + requirements (recommended)

```bash
# Clone the repository
git clone https://github.com/PhucQuan/SAST_tool4pentester.git
cd SAST_tool4pentester

# Check whether your interpreter is suitable
python scripts/doctor_env.py

# Windows PowerShell: prefer official CPython via the `py` launcher
py -3.12 -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Linux / macOS / Git Bash on Windows
source .venv/bin/activate

# Install runtime dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Optional: install AI dependencies for Gemini verification
python -m pip install -r requirements-ai.txt

# Optional: install developer tooling
python -m pip install -r requirements-dev.txt

# Optional: install the `aegis-sast` console command in editable mode
python -m pip install -e . --no-deps

# Set up Gemini API key (optional — tool works without AI verification)
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

If you only need to run the scanner locally, `python -m aegis_sast.cli ...` is enough.
The editable install is only needed when you want the `aegis-sast` command.
`requirements.txt` is the core scanner stack. Gemini verification is now optional and lives in `requirements-ai.txt`.

On Windows, do **not** create the environment from MSYS2/UCRT Python if you want pip-installed native packages to work reliably. If `python scripts/doctor_env.py` reports `mingw_*` or `msys64`, recreate the venv with official CPython first.

### Option 2: Docker

```bash
docker build -t aegis-sast .
docker run --rm -v $(pwd)/target:/scan aegis-sast scan /scan
```

---

## Quick Start

```bash
# Scan a single Python file
python -m aegis_sast.cli scan app.py

# Scan an entire project directory (all languages)
python -m aegis_sast.cli scan ./my_project/

# Scan without AI verification (faster)
python -m aegis_sast.cli scan ./my_project/ --no-ai

# Output only JSON report, to a custom directory
python -m aegis_sast.cli scan ./my_project/ --output json --output-dir ./results/

# Export SARIF for GitHub code scanning or CI pipelines
python -m aegis_sast.cli scan ./my_project/ --output sarif --output-dir ./results/

# Positive smoke sample that should produce findings
python -m aegis_sast.cli scan examples/vulnerable_sqli.py --no-ai --output json --output markdown --output sarif --output-dir reports/manual_smoke
```

### Example Output

```
╭─────────────────────────────────╮
│ 🔒 Aegis-SAST Security Scanner  │
│ AI-Powered Static Analysis Tool │
╰─────────────────────────────────╯

🔍 Scanning: examples/vulnerable_sqli.py

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Metric         ┃     Value ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Files Scanned  │         1 │
│ Total Findings │         5 │
│ 🔴 Critical    │         3 │
│ 🟠 High        │         1 │
│ 🟡 Medium      │         1 │
└────────────────┴───────────┘

⚠️  CRITICAL vulnerabilities found!
```

---

## How to Use Results

Each report (JSON and Markdown) contains for every finding:

- **Vulnerability type** (e.g. `SQL_INJECTION`)
- **Severity** (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`)
- **Source location** — the file and line where untrusted input enters
- **Sink location** — the file and line of the dangerous function
- **AI confidence score** and **remediation recommendation** (when AI is enabled)

---

## Configuration

| CLI Flag | Default | Description |
|---|---|---|
| `--no-ai` | AI enabled | Disable Gemini AI verification |
| `--max-depth` | `5` | Maximum taint propagation depth |
| `--output` | `json,markdown` | Output format(s): `json`, `markdown`, `sarif` |
| `--output-dir` | `reports/` | Directory for report files |
| `--rules` | auto | Path to custom rules YAML file |

If `google-genai` is not installed, the CLI will automatically fall back to non-AI mode after printing a warning.

---

## Writing Custom Rules

Rules are defined in YAML files under `rules/`. Here is the structure:

```yaml
sources:
  - pattern: "request.args.get"
    type: "HTTP_PARAM"
    severity: "HIGH"

sinks:
  sqli:
    - pattern: ".execute("
      type: "SQL_INJECTION"
      severity: "CRITICAL"
      description: "Raw SQL execution"

sanitizers:
  - pattern: "parameterize("
    mitigates: ["SQL_INJECTION"]
    description: "Safe parameterized query"
```

To add a new language: create `rules/<language>.yaml` and implement `aegis_sast/plugins/<language>_plugin.py`.

---

## Limitations

> [!NOTE]
> Understanding the limitations helps interpret results accurately.

| Limitation | Explanation |
|---|---|
| **Intra-project analysis only** | Cross-file tracking works within the same project directory via explicit imports. Third-party library internals are not traversed. |
| **No dynamic analysis** | `__import__()`, `importlib`, runtime reflection are not resolved — only static `from X import Y` statements. |
| **Conservative taint** | When a function has multiple return paths, all are treated as tainted if any is tainted (may cause false positives). |
| **Python cross-file only** | Cross-file tracking currently only supports Python. JS/Java/PHP work intra-file. |
| **Not a WAF replacement** | This tool finds code patterns; it does not test a running application. |

---

## Project Structure

```
aegis_sast/
├── ai/
│   ├── gemini_client.py        # Gemini API integration
│   └── prompts.py              # Vulnerability-specific prompt templates
├── analysis/
│   ├── call_graph.py           # FunctionIndex + ImportResolver (cross-file)
│   ├── rule_engine.py          # YAML rule loader
│   └── vulnerability_detector.py  # Main scan orchestrator
├── core/
│   ├── models.py               # Data models (Vulnerability, TaintSource, etc.)
│   ├── plugin_interface.py     # Abstract base for language plugins
│   └── registry.py             # Plugin auto-registration
└── plugins/
    ├── python_plugin.py        # Python / Flask / Django
    ├── javascript_plugin.py    # Node.js / Express
    ├── java_plugin.py          # Java / Spring
    └── php_plugin.py           # PHP / Laravel
rules/
    ├── python.yaml
    ├── javascript.yaml
    ├── java.yaml
    └── php.yaml
```

---

## Development

```bash
# Lightweight smoke test for config + triage + workflow
python scripts/manual_smoke.py

# Graph-core smoke tests without Tree-sitter
python scripts/manual_graph_smoke.py

# Synthetic Python graph ablation benchmark
python scripts/benchmark_python_graph_ablation.py

# Check interpreter / ABI compatibility before debugging pip failures
python scripts/doctor_env.py

# Run unit tests after installing developer dependencies
python -m pytest tests/ -v

# Run against example vulnerable files
python -m aegis_sast.cli scan examples/ --no-ai
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built as a Penetration Testing portfolio project · Python · Tree-sitter · Gemini AI</sub>
</div>
