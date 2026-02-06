"""
Example: SQL Injection Vulnerabilities

⚠️ WARNING: This file contains intentional security vulnerabilities!
DO NOT use this code in production.

Purpose: Demonstrate SQL injection patterns for testing Aegis-SAST
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)


# VULNERABILITY 1: String concatenation in SQL query
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return str(result)


# VULNERABILITY 2: F-string formatting in SQL query
@app.route('/search')
def search_users():
    search_term = request.args.get('q')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: F-string with user input
    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return str(results)


# VULNERABILITY 3: Format method in SQL query
@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: .format() with user input
    query = "SELECT * FROM users WHERE username='{}' AND password='{}'".format(
        username, password
    )
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return "Login successful"
    return "Login failed"


# VULNERABILITY 4: % operator in SQL query
@app.route('/delete')
def delete_user():
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: % operator with user input
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    
    conn.commit()
    conn.close()
    return "User deleted"


# VULNERABILITY 5: Multi-statement injection
@app.route('/update')
def update_email():
    user_id = request.args.get('id')
    new_email = request.args.get('email')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Allows multi-statement injection
    query = "UPDATE users SET email = '" + new_email + "' WHERE id = " + user_id
    cursor.execute(query)
    
    conn.commit()
    conn.close()
    return "Email updated"


# SAFE EXAMPLE (for comparison)
@app.route('/safe_user')
def get_user_safe():
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    return str(result)


if __name__ == '__main__':
    app.run(debug=True)
