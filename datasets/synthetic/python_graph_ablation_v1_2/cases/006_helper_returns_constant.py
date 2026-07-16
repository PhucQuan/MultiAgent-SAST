import os


def safe_helper(cmd):
    return "echo safe"


def handler():
    cmd = request.args.get("cmd")
    prepared = safe_helper(cmd)
    os.system(prepared)
