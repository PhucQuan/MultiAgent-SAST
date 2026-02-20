# vulnerable_owasp_top10.py
# A mock script containing multiple OWASP vulnerabilities for Aegis-SAST testing.

from flask import Flask, request, render_template_string, redirect, Markup
import requests
import urllib.request
import sqlite3
import xml.etree.ElementTree as ET
import pickle
import yaml
from jinja2 import Template

app = Flask(__name__)

# 1. XSS (Cross-Site Scripting)
@app.route('/xss')
def xss_vuln():
    name = request.args.get('name', 'Guest')
    # SINK: render_template_string
    return render_template_string('<h1>Hello ' + name + '</h1>')


# 2. SSRF (Server-Side Request Forgery)
@app.route('/ssrf')
def ssrf_vuln():
    url = request.args.get('url')
    # SINK: requests.get
    response = requests.get(url)
    return response.text


# 3. NoSQL Injection (Simulated with MongoDB-like syntax)
class MockMongo:
    class users:
        def find(self, query): pass

db = MockMongo()

@app.route('/nosqli')
def nosqli_vuln():
    user_id = request.args.get('id')
    # SINK: db.users.find
    user = db.users.find({"_id": user_id})
    return str(user)


# 4. XXE (XML External Entities)
@app.route('/xxe', methods=['POST'])
def xxe_vuln():
    xml_data = request.data
    # SINK: ElementTree.parse
    tree = ET.parse(xml_data)
    return "XML Parsed"


# 5. IDOR (Insecure Direct Object Reference)
class User:
    class query:
        @staticmethod
        def get(id): pass

@app.route('/idor')
def idor_vuln():
    user_id = request.args.get('user_id')
    # SINK: User.query.get
    account = User.query.get(user_id)
    return "Account details here"


# 6. SSTI (Server-Side Template Injection)
@app.route('/ssti')
def ssti_vuln():
    template_str = request.args.get('template')
    # SINK: Template
    t = Template(template_str)
    return t.render()


# 7. Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize_vuln():
    data = request.data
    # SINK: pickle.loads
    obj = pickle.loads(data)
    
    yaml_data = request.args.get('config')
    # SINK: yaml.unsafe_load
    cfg = yaml.unsafe_load(yaml_data)
    
    return "Deserialized"


# 8. Mass Assignment
class CustomModel:
    def update(self, **kwargs): pass

@app.route('/mass_assignment', methods=['POST'])
def mass_assign_vuln():
    model = CustomModel()
    user_data = request.json
    # SINK: .update(**
    model.update(**user_data)
    return "Updated"


# 9. Open Redirect
@app.route('/redirect')
def open_redirect_vuln():
    next_url = request.args.get('next')
    # SINK: redirect
    return redirect(next_url)

if __name__ == '__main__':
    app.run(debug=True)
