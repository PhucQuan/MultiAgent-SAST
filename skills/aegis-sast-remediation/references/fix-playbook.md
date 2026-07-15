# Remediation Playbook

## Preferred Secure Replacements

- SQL injection: parameterized queries or safe ORM methods
- command injection: argument arrays and allowlists instead of shell strings
- path traversal: canonicalization plus base-directory enforcement
- XSS: context-aware output encoding and safer template APIs
- SSRF: allowlists, URL parsing, internal-network denial
- insecure deserialization: safe loaders or stricter formats

## Fix Review Checklist

- Does the patch eliminate the vulnerable data path?
- Does the patch preserve expected application behavior?
- Does the patch introduce a new auth, validation, or encoding assumption?
- Can the scanner detect the fix as lower risk on rerun?

## Thesis Value

Good remediation notes show the project is not just a detector.
They demonstrate engineering maturity and help justify the “agent” part of the thesis.

