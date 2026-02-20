"""
Prompt templates for Gemini API vulnerability verification.

Contains structured prompts for different vulnerability types.
"""

from aegis_sast.core.models import VulnerabilityType


def get_verification_prompt(
    vuln_type: VulnerabilityType,
    source_code: str,
    dataflow_path: list,
    sink_code: str
) -> str:
    """
    Generate verification prompt for Gemini API.
    
    Args:
        vuln_type: Type of vulnerability
        source_code: Source code snippet
        dataflow_path: List of dataflow steps
        sink_code: Sink code snippet
        
    Returns:
        Formatted prompt string
    """
    
    vuln_descriptions = {
        VulnerabilityType.SQL_INJECTION: {
            "name": "SQL Injection",
            "risk": "Attackers can manipulate database queries to access, modify, or delete data",
            "check": "Verify if user input flows into SQL query without parameterization"
        },
        VulnerabilityType.COMMAND_INJECTION: {
            "name": "Command Injection",
            "risk": "Attackers can execute arbitrary system commands",
            "check": "Verify if user input flows into system command without sanitization"
        },
        VulnerabilityType.CODE_INJECTION: {
            "name": "Code Injection",
            "risk": "Attackers can execute arbitrary code in the runtime",
            "check": "Verify if user input flows into eval/exec/Function without validation"
        },
        VulnerabilityType.PATH_TRAVERSAL: {
            "name": "Path Traversal",
            "risk": "Attackers can access files outside intended directory",
            "check": "Verify if user input flows into file operations without path validation"
        },
        VulnerabilityType.XSS: {
            "name": "Cross-Site Scripting (XSS)",
            "risk": "Attackers can inject malicious scripts into web pages viewed by other users",
            "check": "Verify if user input is rendered in HTML/JS context without HTML escaping (htmlspecialchars, escape, etc.)"
        },
        VulnerabilityType.SSRF: {
            "name": "Server-Side Request Forgery (SSRF)",
            "risk": "Attacker can make the server send requests to internal network services or arbitrary URLs",
            "check": "Verify if user-supplied URL is used in HTTP request functions without a whitelist/validation (requests.get, axios.get, curl, etc.)"
        },
        VulnerabilityType.NOSQL_INJECTION: {
            "name": "NoSQL Injection",
            "risk": "Attackers can manipulate NoSQL queries (MongoDB, etc.) to access or modify data",
            "check": "Verify if user input is passed directly into a MongoDB/NoSQL find/query operation without sanitization"
        },
        VulnerabilityType.XXE: {
            "name": "XML External Entity (XXE)",
            "risk": "Attackers can read internal files or make server-side requests via malicious XML",
            "check": "Verify if XML is parsed from user input without disabling external entity resolution"
        },
        VulnerabilityType.IDOR: {
            "name": "Insecure Direct Object Reference (IDOR)",
            "risk": "Attacker can access/modify resources of other users by manipulating object IDs",
            "check": "Verify if user-supplied ID is used to fetch a database record without ownership check"
        },
        VulnerabilityType.SSTI: {
            "name": "Server-Side Template Injection (SSTI)",
            "risk": "Attackers can inject template directives that execute arbitrary code on the server",
            "check": "Verify if user input flows into a template engine (Jinja2, Twig, Smarty) constructor or render function"
        },
        VulnerabilityType.INSECURE_DESERIALIZATION: {
            "name": "Insecure Deserialization",
            "risk": "Attackers can achieve remote code execution by providing tampered serialized objects",
            "check": "Verify if untrusted data is deserialized via pickle.loads, yaml.unsafe_load, ObjectInputStream.readObject, or unserialize() without integrity check"
        },
        VulnerabilityType.MASS_ASSIGNMENT: {
            "name": "Mass Assignment",
            "risk": "Attackers can set unauthorized model attributes (e.g., is_admin=True) by injecting extra fields",
            "check": "Verify if user-provided dict/JSON is passed directly into model.update() or model.create() without an allowlist of permitted fields"
        },
        VulnerabilityType.OPEN_REDIRECT: {
            "name": "Open Redirect",
            "risk": "Attackers can redirect users to attacker-controlled URLs, enabling phishing attacks",
            "check": "Verify if user-supplied URL/path is used in redirect() without a whitelist or domain check"
        },
    }
    
    desc = vuln_descriptions.get(
        vuln_type,
        {
            "name": vuln_type.value,
            "risk": "Security vulnerability",
            "check": "Verify if this represents a real security risk"
        }
    )
    
    # Format dataflow path
    path_str = "\n".join([f"  {i+1}. {step}" for i, step in enumerate(dataflow_path)])
    
    prompt = f"""You are a senior security analyst performing static code analysis.

**Vulnerability Type**: {desc['name']}

**Security Risk**: {desc['risk']}

**Analysis Task**: {desc['check']}

**SOURCE (Untrusted Input)**:
```
{source_code}
```

**DATAFLOW PATH**:
{path_str}

**SINK (Dangerous Function)**:
```
{sink_code}
```

**Your Task**:
1. Analyze if untrusted data from SOURCE reaches SINK without proper sanitization
2. Check if any sanitization in the dataflow is sufficient and effective
3. Determine if this is a true vulnerability or false positive
4. Provide specific remediation advice

**Respond ONLY with valid JSON** in this exact format:
{{
  "is_vulnerable": true or false,
  "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
  "confidence": 0.0 to 1.0,
  "explanation": "Brief technical explanation of why this is/isn't vulnerable",
  "recommendation": "Specific code fix recommendation"
}}

**Important**:
- If you see parameterized queries (?, %s with tuples), it's NOT vulnerable to SQLi
- If you see shlex.quote() or similar, it's likely NOT vulnerable to command injection
- If you see path validation (os.path.abspath, .resolve()), it's likely NOT vulnerable to path traversal
- Be precise and technical in your analysis
"""
    
    return prompt


def get_batch_verification_prompt(vulnerabilities: list) -> str:
    """
    Generate batch verification prompt for multiple vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability data
        
    Returns:
        Formatted batch prompt
    """
    # For now, we'll verify one at a time for better accuracy
    # Batch verification could be added later for performance
    pass
