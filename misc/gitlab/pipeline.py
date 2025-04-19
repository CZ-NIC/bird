import importlib
import jinja2
import sys
import yaml

assert(sys.argv[1])

# Prepare Jinja2 environment
env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))

# Load and process input data
data = yaml.safe_load(env.get_template(f'{sys.argv[1]}-list.yml.j2').render())

# Check the updater script
try:
    data = importlib.import_module(f'{sys.argv[1]}-update').update(data)
except ModuleNotFoundError:
    # No fail for nonexistent updater
    pass

# Load the actual template
template = env.get_template(f'{sys.argv[1]}-template.yml.j2')

# Print the pipeline header (if exists)
try:
    print(env.get_template('{sys.argv[1]}-header.yml.j2').render())
except jinja2.exceptions.TemplateNotFound:
    pass

# Render the template
for item in data:
    print(template.render(item))
    print()
    print()

# Print the pipeline footer (if exists)
try:
    print(env.get_template('{sys.argv[1]}-footer.yml.j2').render())
except jinja2.exceptions.TemplateNotFound:
    pass
