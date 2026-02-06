"""
Example: Remote Code Execution (RCE) Vulnerabilities

⚠️ WARNING: This file contains intentional security vulnerabilities!
DO NOT use this code in production.

Purpose: Demonstrate command injection patterns for testing Aegis-SAST
"""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


# VULNERABILITY 1: os.system() with user input
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    
    # Vulnerable: Direct command execution with user input
    os.system(f'ping -c 4 {host}')
    
    return f"Pinged {host}"


# VULNERABILITY 2: subprocess with shell=True
@app.route('/whois')
def whois_lookup():
    domain = request.args.get('domain')
    
    # Vulnerable: shell=True allows command injection
    result = subprocess.run(
        f'whois {domain}',
        shell=True,
        capture_output=True
    )
    
    return result.stdout.decode()


# VULNERABILITY 3: eval() with user input
@app.route('/calc')
def calculator():
    expression = request.args.get('expr')
    
    # Vulnerable: eval() executes arbitrary Python code
    result = eval(expression)
    
    return f"Result: {result}"


# VULNERABILITY 4: exec() with user input
@app.route('/execute')
def execute_code():
    code = request.form.get('code')
    
    # Vulnerable: exec() runs arbitrary Python code
    exec(code)
    
    return "Code executed"


# VULNERABILITY 5: os.popen() with user input
@app.route('/list')
def list_directory():
    directory = request.args.get('dir')
    
    # Vulnerable: os.popen() allows command injection
    output = os.popen(f'ls -la {directory}').read()
    
    return f"<pre>{output}</pre>"


# VULNERABILITY 6: subprocess.call() with concatenation
@app.route('/download')
def download_file():
    url = request.args.get('url')
    
    # Vulnerable: Command injection via URL parameter
    subprocess.call('wget ' + url, shell=True)
    
    return "Download started"


# VULNERABILITY 7: compile() and eval() combination
@app.route('/run')
def run_expression():
    user_code = request.args.get('code')
    
    # Vulnerable: compile() + eval() allows arbitrary code execution
    compiled = compile(user_code, '<string>', 'eval')
    result = eval(compiled)
    
    return str(result)


# VULNERABILITY 8: os.system() with string concatenation
@app.route('/backup')
def backup_database():
    db_name = request.args.get('database')
    
    # Vulnerable: String concatenation in system command
    command = "mysqldump -u root " + db_name + " > /tmp/backup.sql"
    os.system(command)
    
    return "Backup created"


# SAFE EXAMPLE (for comparison)
@app.route('/safe_ping')
def safe_ping():
    host = request.args.get('host')
    
    # SAFE: Using list arguments, no shell
    try:
        result = subprocess.run(
            ['ping', '-c', '4', host],
            shell=False,
            capture_output=True,
            timeout=10
        )
        return result.stdout.decode()
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Error: {e}"


if __name__ == '__main__':
    app.run(debug=True)
