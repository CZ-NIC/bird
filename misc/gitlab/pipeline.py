#!/usr/bin/env python3

import importlib
import jinja2
import pathlib
import subprocess
import sys
import yaml

# Find where we are
localdir = pathlib.Path(__file__).parent

# Prepare Jinja2 environment
env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(localdir)))
env.filters.update({ "to_yaml": lambda x: "" if type(x) is jinja2.runtime.Undefined else yaml.dump(x).rstrip() })

# Load and process input data
try:
    data = yaml.safe_load(rendered := env.get_template(f'data.yml.j2').render({}))
except yaml.parser.ParserError as e:
    print("Failed to render input data, generated output here:")
    print(rendered)
    raise e

# Load the actual template
template = env.get_template(f'template.yml.j2')

# Render the template
final = template.render({ **data })

# YAML is picky about tabs, forbid them
assert('\t' not in final)

# Produce output
print(final)
