import os


def relay(cmd):
    alias = cmd
    return alias


def handler():
    cmd = request.args.get("cmd")
    prepared = relay(cmd)
    os.system(prepared)
