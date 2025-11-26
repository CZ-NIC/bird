import logging
import subprocess

# Run an external command
class CommandError(Exception):
    def __str__(self):
        return f"""Command {self.args[0].args} failed with code {self.args[0].returncode}.
        {self.args[0].stdout.decode()}
        {self.args[0].stderr.decode()}"""

def Command(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode != 0:
        raise CommandError(result)

    return result.stdout.decode().split("\n")

