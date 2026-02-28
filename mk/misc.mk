# Gitlab CI tests
gitlab-venv: .gitlab-ci.yml
gitlab-venv: USE_VENV := VENV

gitlab-local: .gitlab-ci.yml
gitlab-local: USE_VENV :=

.gitlab-ci.yml: $(addprefix misc/gitlab/,pipeline.py data.yml.j2 template.yml.j2)
	($(if $(USE_VENV),\
		VENV=$$(mktemp -d); \
		python3 -m venv $$VENV; \
		. $$VENV/bin/activate; \
		pip3 install jinja2 pyaml; \
		,) \
		python3 misc/gitlab/pipeline.py > $@; \
		$(if $(USE_VENV),rm -rf $$VENV,) \
		)

.PHONY: gitlab-venv gitlab-local
NOTARGETGOALS += gitlab-venv gitlab-local .gitlab-ci.yml
