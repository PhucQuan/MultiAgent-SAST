"""
Example: Insecure Deserialization Vulnerabilities

WARNING: This file contains intentional security vulnerabilities!
DO NOT use this code in production.

Purpose: Demonstrate insecure deserialization patterns for testing Aegis-SAST
"""

from flask import Flask, request
import pickle
import yaml

app = Flask(__name__)


# VULNERABILITY 1: Untrusted pickle payload
@app.route("/pickle", methods=["POST"])
def load_pickle():
    payload = request.data

    # Vulnerable: pickle on untrusted input can lead to code execution
    obj = pickle.loads(payload)

    return {"loaded": str(obj)}


# VULNERABILITY 2: Unsafe YAML loader
@app.route("/yaml")
def load_yaml():
    config_text = request.args.get("config")

    # Vulnerable: unsafe YAML loader on attacker-controlled input
    cfg = yaml.unsafe_load(config_text)

    return {"config": str(cfg)}


# VULNERABILITY 3: Generic yaml.load without safe loader
@app.route("/yaml-load", methods=["POST"])
def load_yaml_generic():
    config_text = request.data

    # Vulnerable: yaml.load without safe loader
    cfg = yaml.load(config_text)

    return {"config": str(cfg)}


# SAFE EXAMPLE (for comparison)
@app.route("/safe-yaml")
def load_yaml_safely():
    config_text = request.args.get("config", "")

    # SAFE: safe_load avoids arbitrary object construction
    cfg = yaml.safe_load(config_text)

    return {"config": cfg}


if __name__ == "__main__":
    app.run(debug=True)
