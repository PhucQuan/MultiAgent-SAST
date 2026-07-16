import os


def handler():
    cmd = request.args.get("cmd")
    cmd = "echo safe"
    os.system(cmd)
