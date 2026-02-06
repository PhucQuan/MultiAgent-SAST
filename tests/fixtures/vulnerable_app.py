"""
Sample vulnerable Python application for testing Aegis-SAST.

Contains intentional security vulnerabilities for demonstration purposes.
DO NOT USE IN PRODUCTION!
"""

import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)


# ===== SQL INJECTION VULNERABILITIES =====

@app.route('/login')
def vulnerable_login():
    """VULN: SQL Injection - User input directly in query"""
    username = request.args.get('username')
    password = request.args.get('password')
    
    # CRITICAL: String formatting with user input
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)  # ← SINK: SQL Injection
    
    return "Login successful"


@app.route('/search')
def vulnerable_search():
    """VULN: SQL Injection - Concatenation"""
    search_term = request.form.get('query', '')
    
    # CRITICAL: String concatenation
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    
    conn = sqlite3.connect('database.db')
    result = conn.execute(query)  # ← SINK: SQL Injection
    
    return str(result.fetchall())


# ===== COMMAND INJECTION VULNERABILITIES =====

@app.route('/ping')
def vulnerable_ping():
    """VULN: Command Injection - os.system"""
    host = request.args.get('host', 'localhost')
    
    # CRITICAL: Direct system command with user input
    os.system(f"ping -c 4 {host}")  # ← SINK: Command Injection
    
    return "Ping completed"


@app.route('/backup')
def vulnerable_backup():
    """VULN: Command Injection - subprocess without sanitization"""
    filename = request.args.get('file')
    
    # CRITICAL: subprocess.call with user input
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)  # ← SINK: Command Injection
    
    return "Backup created"


@app.route('/execute')
def vulnerable_execute():
    """VULN: Code Injection - eval"""
    code = request.args.get('code', '')
    
    # CRITICAL: eval with user input
    result = eval(code)  # ← SINK: Code Injection
    
    return str(result)


# ===== PATH TRAVERSAL VULNERABILITIES =====

@app.route('/read')
def vulnerable_file_read():
    """VULN: Path Traversal - Direct file access"""
    filepath = request.args.get('file')
    
    # CRITICAL: Direct file open with user input
    with open(filepath, 'r') as f:  # ← SINK: Path Traversal
        content = f.read()
    
    return content


@app.route('/download')
def vulnerable_download():
    """VULN: Path Traversal - os.path.join without validation"""
    filename = request.args.get('filename')
    
    # MEDIUM: Path construction without validation
    filepath = os.path.join('/var/www/uploads', filename)
    
    with open(filepath, 'rb') as f:  # ← SINK: Path Traversal
        data = f.read()
    
    return data


# ===== SAFE EXAMPLES (Should not trigger) =====

@app.route('/safe_login')
def safe_login():
    """SAFE: Parameterized query"""
    username = request.args.get('username')
    password = request.args.get('password')
    
    # SAFE: Using parameterized query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, (username, password))  # ← SAFE: Parameterized
    
    return "Login successful"


@app.route('/safe_command')
def safe_command():
    """SAFE: Using shlex.quote"""
    import shlex
    
    host = request.args.get('host')
    
    # SAFE: Sanitized with shlex.quote
    safe_host = shlex.quote(host)
    os.system(f"ping -c 4 {safe_host}")
    
    return "Ping completed"


@app.route('/safe_file')
def safe_file():
    """SAFE: Path validation"""
    filename = request.args.get('filename')
    
    # SAFE: Path validation with realpath
    base_dir = '/var/www/uploads'
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    
    # Ensure file is within base_dir
    if not filepath.startswith(base_dir):
        return "Access denied", 403
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    return content


if __name__ == '__main__':
    app.run(debug=True)
