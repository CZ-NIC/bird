#!/usr/bin/env python3

import importlib
import jinja2
import pathlib
import subprocess
import sys
import yaml

# Find where we are
_, template_file, data_file, *more = sys.argv
hm = { k: v for k,v in [ x.split("=", 1) for x in more ] }

# Crash helper
def fail(msg):
    raise Exception(msg)

# Prepare Jinja2 environment
env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
env.globals['fail'] = fail
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
final = template.render({ **data, **hm })

# Produce output
print(final)
