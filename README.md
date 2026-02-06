# 🔒 Aegis-SAST

**AI-Powered Static Application Security Testing CLI Tool**

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

Aegis-SAST is a powerful CLI tool designed for Pentesters to perform static code analysis and detect security vulnerabilities (SQL Injection, RCE, Path Traversal) using **Tree-sitter** for AST parsing and **Gemini AI** for intelligent vulnerability verification.

---

## ✨ Features

- **🎯 Hybrid Analysis**: Combines Tree-sitter pattern matching with AI verification for high accuracy
- **🔌 Plugin Architecture**: Extensible design for multi-language support (Python first, more coming)
- **🧠 Inter-procedural Taint Analysis**: Tracks data flow across functions and files
- **📝 Custom Rules**: Define your own sources, sinks, and sanitizers via YAML/JSON
- **💾 Smart Caching**: Hash-based caching reduces AI API costs by 50%+
- **📊 Dual Reporting**: JSON for CI/CD integration + Markdown for human readers
- **⚡ Cost-Optimized**: Only calls AI API when necessary (hybrid approach)

---

## 🎯 Supported Vulnerabilities

| Category | Types |
|----------|-------|
| **Injection** | SQL Injection, Command Injection, Code Injection |
| **Path Issues** | Path Traversal, Directory Traversal |
| **Future** | XSS, XXE, SSRF, Deserialization |

---

## 📋 Requirements

- Python 3.10+
- Gemini API Key ([Get one here](https://ai.google.dev/))
- Poetry (recommended) or pip

---

## 🚀 Quick Start

> **⚡ New to Aegis-SAST?** Check out the [**5-Minute Quick Start Guide**](QUICKSTART.md) for a step-by-step tutorial!

## 📦 Installation

### Step 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/PhucQuan/aegis-sast.git
cd aegis-sast
```

### Step 2: Install Dependencies

**Option A: Using pip (Simple)**

```bash
# Install in editable mode
pip install -e .

# Verify installation
aegis-sast --version
```

**Option B: Using Poetry (Recommended for Development)**

```bash
# Install Poetry first (if not installed)
pip install poetry

# Install all dependencies
poetry install

# Activate virtual environment
poetry shell

# Verify installation
aegis-sast --version
```

---

### Step 3: Configure API Key

1. **Copy environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` and add your Gemini API key** ([Get FREE API key](https://ai.google.dev/)):
   ```ini
   GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXX  # Replace with your actual key
   GEMINI_MODEL=gemini-1.5-flash
   
   CACHE_ENABLED=true
   ENABLE_AI_VERIFICATION=true
   MAX_ANALYSIS_DEPTH=5
   ```

3. **(Optional) Customize rules**: Edit `rules/python.yaml` to define custom sources/sinks

### Step 4: Test Installation

```bash
# Test with example vulnerable code
aegis-sast scan examples/

# Expected: Should detect ~12 vulnerabilities
# Check reports/ directory for results
```

✅ **Installation complete!** You can now scan your own projects.

---

## 📖 Usage

### Scan Your Project

```bash
# Scan a specific file
aegis-sast scan /path/to/your/file.py

# Scan entire project directory
aegis-sast scan /path/to/your/project

# Scan current directory
aegis-sast scan .
```

### Quick Test with Examples

```bash
# Test the tool on example vulnerable code
aegis-sast scan examples/

# Scan specific example
aegis-sast scan examples/vulnerable_sqli.py
```

### Advanced Options

```bash
# Disable AI verification (faster, less accurate)
aegis-sast scan /path/to/project --no-ai

# Use custom security rules
aegis-sast scan /path/to/project --rules custom_rules.yaml

# Specify output formats
aegis-sast scan /path/to/project -o json          # JSON only
aegis-sast scan /path/to/project -o json -o markdown  # Both

# Custom output directory
aegis-sast scan /path/to/project --output-dir ./security-reports

# Adjust analysis depth (default: 5)
aegis-sast scan /path/to/project --max-depth 10
```

### View Help

```bash
aegis-sast --help
aegis-sast scan --help
```

---

## 📊 Example Output

### Markdown Report

```markdown
# 🔒 Aegis-SAST Security Report

**Target**: /home/user/vulnerable_app
**Date**: 2026-02-05 17:20:00
**Total Findings**: 8 (🔴 2 Critical | 🟠 3 High | 🟡 3 Medium)

---

## 🔴 Critical Vulnerabilities

### VULN-001: SQL Injection in `app.py:42`

**Type**: SQL_INJECTION  
**Severity**: CRITICAL

**Dataflow**:
1. `request.args.get('user_id')` at line 40 → **SOURCE**
2. `query = f"SELECT * FROM users WHERE id={user_id}"` at line 41
3. `cursor.execute(query)` at line 42 → **SINK**

**AI Analysis**:
❌ **Vulnerable**: User input directly concatenated into SQL query

**Recommendation**:
Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))`
```

---

## 🏗️ Architecture

```
aegis-sast/
├── aegis_sast/
│   ├── core/              # Core models, config, plugin interface
│   ├── analysis/          # Taint engine, rule engine
│   ├── plugins/           # Language-specific analyzers
│   ├── ai/                # Gemini client, caching
│   ├── reporting/         # JSON/Markdown exporters
│   └── utils/             # File scanning, logging
├── rules/                 # Default security rules
└── tests/                 # Unit & integration tests
```

**Design Patterns**:
- **Strategy Pattern**: Plugin architecture for language support
- **Factory Pattern**: Plugin registry and auto-discovery
- **Repository Pattern**: Cache management

---

## 🔧 Development

### Run Tests

```bash
poetry run pytest tests/ -v --cov=aegis_sast
```

### Code Formatting

```bash
poetry run black aegis_sast/
poetry run ruff check aegis_sast/
```

---

## 🛣️ Roadmap

- [x] Python language support
- [x] Inter-procedural taint analysis
- [x] Gemini AI integration with caching
- [x] JSON & Markdown reports
- [ ] JavaScript/TypeScript plugin
- [ ] PHP plugin
- [ ] VSCode extension
- [ ] CI/CD integration templates
- [ ] Web dashboard

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

---

## 📧 Contact

- **Author**: PhucQuan
- **GitHub**: [PhucQuan/FintechLab_Pentest]
- **Issues**: [GitHub Issues](https://github.com/yourusername/aegis-sast/issues)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Always obtain proper authorization before testing any system.
