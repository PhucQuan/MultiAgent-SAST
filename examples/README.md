# 🧪 Example Vulnerable Code

This directory contains **intentionally vulnerable** Python code for testing Aegis-SAST.

> [!WARNING]
> **DO NOT use this code in production!** These files contain security vulnerabilities for educational and testing purposes only.

## How this folder differs from others

- `examples/` is for user-facing demos and quick first-run scans
- `test_projects/` is for developer smoke tests and debugging
- `benchmarks/fixtures/` is for evaluation-grade research fixtures

## 📁 Files

### 1. `vulnerable_sqli.py` - SQL Injection Examples

Demonstrates common SQL injection vulnerabilities:
- String concatenation in queries
- F-string formatting with user input
- No parameterized queries

**Test it:**
```bash
aegis-sast scan examples/vulnerable_sqli.py
```

**Expected findings:** 3-5 SQL Injection vulnerabilities (CRITICAL severity)

---

### 2. `vulnerable_rce.py` - Remote Code Execution

Shows dangerous command execution patterns:
- `os.system()` with user input
- `subprocess` without proper sanitization
- `eval()` and `exec()` misuse

**Test it:**
```bash
aegis-sast scan examples/vulnerable_rce.py
```

**Expected findings:** 4-6 Command Injection vulnerabilities (CRITICAL severity)

---

### 3. `vulnerable_path_traversal.py` - Path Traversal

Illustrates file path vulnerabilities:
- Direct path concatenation
- Missing path validation
- Unsafe file operations

**Test it:**
```bash
aegis-sast scan examples/vulnerable_path_traversal.py
```

**Expected findings:** 3-4 Path Traversal vulnerabilities (HIGH severity)

---

### 4. `vulnerable_deserialization.py` - Insecure Deserialization

Demonstrates unsafe object loading patterns:
- `pickle.loads()` on untrusted input
- `yaml.unsafe_load()` on user-controlled content
- `yaml.load()` without a safe loader

**Test it:**
```bash
aegis-sast scan examples/vulnerable_deserialization.py
```

**Expected findings:** 2-3 Insecure Deserialization vulnerabilities (CRITICAL severity)

---

### 5. `vulnerable_ssrf.py` - Server-Side Request Forgery

Shows unsafe outbound HTTP requests driven by user input:
- `requests.get()` with untrusted destinations
- `urllib.request.urlopen()` on user-controlled URLs
- A constant trusted destination example for contrast

**Test it:**
```bash
aegis-sast scan examples/vulnerable_ssrf.py
```

**Expected findings:** 2-3 SSRF vulnerabilities (HIGH severity)

---

## 🚀 Quick Test

Scan all examples at once:

```bash
# Scan entire examples directory
aegis-sast scan examples/

# Without AI verification (faster)
aegis-sast scan examples/ --no-ai

# JSON output only
aegis-sast scan examples/ -o json
```

---

## 📊 What to Expect

After scanning, you should see:
- **Console summary** with vulnerability counts
- **JSON report** in `reports/scan_TIMESTAMP.json`
- **Markdown report** in `reports/scan_TIMESTAMP.md`

Example output:
```
🔒 Aegis-SAST Security Scanner

✓ AI verification enabled

🔍 Scanning: examples/

Analysis complete!

====================================================================
                           Scan Summary                            
====================================================================
Target                examples
Files Scanned         3
Duration              2.45s

Total Findings        12
🔴 Critical          9
🟠 High              3

⚠️ CRITICAL vulnerabilities found!
```

---

## 🎯 Learning Points

By examining these examples, you'll understand:
1. **What patterns** Aegis-SAST detects
2. **How taint analysis works** (tracking user input → dangerous sinks)
3. **AI verification benefits** (reducing false positives)
4. **Report formats** for integration into your workflow

---

## 💡 Next Steps

After testing these examples:
1. ✅ Run Aegis-SAST on **your own projects**
2. ✅ Customize rules in `rules/python.yaml`
3. ✅ Integrate into your CI/CD pipeline
4. ✅ Review the generated reports

Happy testing! 🔒
