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
            "risk": "Attackers can execute arbitrary Python code",
            "check": "Verify if user input flows into eval/exec without validation"
        },
        VulnerabilityType.PATH_TRAVERSAL: {
            "name": "Path Traversal",
            "risk": "Attackers can access files outside intended directory",
            "check": "Verify if user input flows into file operations without path validation"
        }
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
