import subprocess


def dynamic_python(code: str) -> None:
    # ruleid: decky.python.dynamic-execution
    exec(code)


def shell_command(command: str) -> None:
    # ruleid: decky.python.shell-command
    subprocess.run(command, shell=True)


def safe_command() -> None:
    # ok: decky.python.shell-command
    subprocess.run(["echo", "safe"], check=True)


def ordinary_function(value: str) -> str:
    # ok: decky.python.dynamic-execution
    return value.upper()
