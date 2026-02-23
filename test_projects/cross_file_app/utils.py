"""
utils.py — Cross-file taint test: SOURCE is defined here.

This simulates a helper module that reads user input from an HTTP request
and returns it WITHOUT any sanitization.  A separate file (app.py) imports
this function and passes the return value to a dangerous sink.

Aegis-SAST Level-B cross-file detection should flag the flow:
    get_command() return value  →  os.system() in app.py
"""
from flask import request


def get_command():
    """Return raw user input — TAINTED return value."""
    cmd = request.args.get("cmd")   # SOURCE: HTTP query parameter
    return cmd
