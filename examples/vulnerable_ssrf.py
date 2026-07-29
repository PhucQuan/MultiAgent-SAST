"""
Example: SSRF Vulnerabilities

WARNING: This file contains intentional security vulnerabilities.
DO NOT use this code in production.

Purpose: Demonstrate outbound-request sinks for testing Aegis-SAST.
"""

import urllib.request
from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)


# VULNERABILITY 1: Direct outbound GET to a user-controlled URL
@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    response = requests.get(target, timeout=3)
    return response.text


# VULNERABILITY 2: urlopen() on a user-controlled destination
@app.route("/preview")
def preview():
    asset_url = request.args.get("asset")
    with urllib.request.urlopen(asset_url) as response:
        return response.read().decode("utf-8", errors="replace")


# VULNERABILITY 3: Another requests.get() flow for benchmark coverage
@app.route("/avatar")
def avatar():
    image_url = request.args.get("image_url")
    response = requests.get(image_url, timeout=2)
    return response.content


# SAFE EXAMPLE: destination comes from trusted server-side configuration
@app.route("/safe-status")
def safe_status():
    trusted_target = "https://status.example.com/health"
    parsed = urlparse(trusted_target)
    response = requests.get(parsed.geturl(), timeout=2)
    return response.text


if __name__ == "__main__":
    app.run(debug=True)
