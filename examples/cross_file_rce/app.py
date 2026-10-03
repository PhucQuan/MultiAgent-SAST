from flask import Flask, request
from service import process_backup

app = Flask(__name__)

@app.route("/backup")
def backup_route():
    target_db = request.args.get("db")
    # Cross-file invocation to service module
    process_backup(target_db)
    return "Backup initiated"

if __name__ == "__main__":
    app.run()
