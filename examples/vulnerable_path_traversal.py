"""
Example: Path Traversal Vulnerabilities

⚠️ WARNING: This file contains intentional security vulnerabilities!
DO NOT use this code in production.

Purpose: Demonstrate path traversal patterns for testing Aegis-SAST
"""

import os
from pathlib import Path
from flask import Flask, request, send_file

app = Flask(__name__)


# VULNERABILITY 1: Direct path concatenation
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    # Vulnerable: Direct concatenation allows ../../../etc/passwd
    file_path = '/var/www/uploads/' + filename
    
    return send_file(file_path)


# VULNERABILITY 2: os.path.join() without validation
@app.route('/read')
def read_file():
    filename = request.args.get('filename')
    
    # Vulnerable: os.path.join doesn't prevent traversal
    file_path = os.path.join('/var/www/files', filename)
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    return content


# VULNERABILITY 3: F-string path construction
@app.route('/image')
def get_image():
    image_name = request.args.get('name')
    
    # Vulnerable: F-string allows path traversal
    image_path = f'/var/www/images/{image_name}'
    
    return send_file(image_path)


# VULNERABILITY 4: Path().joinpath() without validation
@app.route('/document')
def get_document():
    doc_name = request.args.get('doc')
    
    # Vulnerable: pathlib doesn't prevent traversal
    base_dir = Path('/var/www/documents')
    doc_path = base_dir.joinpath(doc_name)
    
    return send_file(str(doc_path))


# VULNERABILITY 5: Open file with user-controlled path
@app.route('/config')
def read_config():
    config_file = request.args.get('config')
    
    # Vulnerable: Direct file opening
    full_path = '/etc/app/configs/' + config_file
    
    with open(full_path) as f:
        data = f.read()
    
    return data


# VULNERABILITY 6: Delete file with path traversal
@app.route('/delete')
def delete_file():
    filename = request.args.get('file')
    
    # Vulnerable: Allows deletion of arbitrary files
    file_path = os.path.join('/tmp/uploads', filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        return "File deleted"
    
    return "File not found"


# VULNERABILITY 7: Directory listing with traversal
@app.route('/list')
def list_directory():
    directory = request.args.get('dir')
    
    # Vulnerable: Can list any directory
    path = '/var/www/data/' + directory
    
    files = os.listdir(path)
    
    return {'files': files}


# SAFE EXAMPLE (for comparison)
@app.route('/safe_download')
def safe_download():
    filename = request.args.get('file')
    
    # SAFE: Validate filename and prevent traversal
    # Remove any path separators
    safe_filename = os.path.basename(filename)
    
    # Ensure filename doesn't contain dangerous patterns
    if '..' in safe_filename or '/' in safe_filename or '\\' in safe_filename:
        return "Invalid filename", 400
    
    # Use absolute path and verify it's within allowed directory
    base_dir = os.path.abspath('/var/www/uploads')
    file_path = os.path.abspath(os.path.join(base_dir, safe_filename))
    
    # Verify the resolved path is still within base directory
    if not file_path.startswith(base_dir):
        return "Access denied", 403
    
    if os.path.exists(file_path):
        return send_file(file_path)
    
    return "File not found", 404


if __name__ == '__main__':
    app.run(debug=True)
