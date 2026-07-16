import os


def handler():
    cmd = request.args.get("cmd")
    return "blocked"
    os.system(cmd)
