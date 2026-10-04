import os

def execute_shell(cmd):
    # Dangerous sink: os.system
    os.system(cmd)
