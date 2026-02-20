from flask import Flask, request
import os
import subprocess
from database import get_user_info
from utils import read_system_file

app = Flask(__name__)

# 1. Local Taint (RCE) - Should be detected
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    if ip:
        # Taint flows from ip -> cmd -> os.system
        cmd = f"ping -c 4 {ip}"
        
        # Thêm các chặng gán biến (Alias) để test tính năng Dataflow Tracking mới nâng cấp
        alias_cmd = cmd
        final_cmd = alias_cmd
        
        os.system(final_cmd)
        return "Ping executing"
    return "Provide IP"

# 2. Cross-file Taint (SQLi) - Requires Inter-procedural analysis
@app.route('/user')
def get_user():
    username = request.args.get('username')
    if username:
        # Taint flows from username -> get_user_info (in database.py)
        user_data = get_user_info(username)
        return f"User data: {user_data}"
    return "Provide username"

# 3. Cross-file Taint (Path Traversal) - Requires Inter-procedural analysis
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    if filename:
        # Taint flows from filename -> read_system_file (in utils.py)
        content = read_system_file(filename)
        return f"File content: {content}"
    return "Provide file"

# 4. Local Taint (Command Injection) - Should be detected
@app.route('/nslookup')
def lookup():
    domain = request.args.get('domain')
    if domain:
        # Taint flows from domain -> subprocess.run
        # Lại thêm các chặng gán biến để làm khó tool
        a = domain
        b = a
        target = b
        
        subprocess.run(f"nslookup {target}", shell=True)
        return "Lookup executing"
    return "Provide domain"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
