#!/usr/bin/env python3

import importlib
import jinja2
import pathlib
import subprocess
import sys
import yaml

# Find where we are
_, template_file, data_file, *_ = sys.argv

# Prepare Jinja2 environment
env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
env.filters.update({ "to_yaml": lambda x: "" if type(x) is jinja2.runtime.Undefined else yaml.dump(x).rstrip() })

# Load and process input data
try:
    data = yaml.safe_load(rendered := env.get_template(data_file).render({}))
except yaml.parser.ParserError as e:
    print("Failed to render input data, generated output here:")
    print(rendered)
    raise e

# Load the actual template
template = env.get_template(template_file)

# Render the template
final = template.render({ **data })

# YAML is picky about tabs, forbid them
assert('\t' not in final)

# Produce output
print(final)
