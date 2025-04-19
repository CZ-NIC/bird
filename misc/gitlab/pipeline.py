#!/usr/bin/env python3

import importlib
import jinja2
import subprocess
import sys
import yaml

# Load Git information
def git(*args):
    res = subprocess.run([ "git", *args ], capture_output=True)
    if res.returncode == 0:
        return res.stdout.decode()

    print("Git show failed with return code", res.returncode)
    print(res.stdout.decode())
    print(res.stderr.decode())
    exit(1)

# Files changed in last commit
gitinfo = {
        "last_commit": {
            "files": [ line[1:].split(' ')[0] for line in git("show", "--stat", "--oneline").split('\n')[1:-2] ]
            }
        }

# Prepare Jinja2 environment
env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))
env.filters.update({ "to_yaml": lambda x: "" if type(x) is jinja2.runtime.Undefined else yaml.dump(x) })

# Load and process input data
try:
    data = yaml.safe_load(rendered := env.get_template(f'data.yml.j2').render(gitinfo))
except yaml.parser.ParserError as e:
    print("Failed to render input data, generated output here:")
    print(rendered)
    raise e

# Load the actual template
template = env.get_template(f'template.yml.j2')

# Render the template
print(template.render({ **data, "git": gitinfo }))
