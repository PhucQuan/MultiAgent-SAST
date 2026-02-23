"""
app.py — Cross-file taint test: SINK is defined here.

Imports get_command() from utils.py.  The return value of get_command() is
tainted (raw HTTP input) but this file passes it directly to os.system()
without any validation or sanitization.

Expected Aegis-SAST finding:
  [CRITICAL] COMMAND_INJECTION
  Source: request.args.get('cmd')  →  utils.py:14
  Via:    get_command() return value
  Sink:   os.system(cmd)           →  app.py:18
"""
import os
from flask import Flask
from utils import get_command    # cross-file import

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = get_command()          # tainted variable — returned from utils.py
    os.system(cmd)               # SINK: COMMAND_INJECTION
    return "done"


if __name__ == "__main__":
    app.run(debug=True)
