# Gitlab CI tests
#GITLAB_SECTIONS := template

#$(s)%.yml: $(s)pipeline.py $(s)%.yml.j2 $(s)data.yml.j2
.gitlab-ci.yml: $(s)pipeline.py $(s)template.yml.j2 $(s)data.yml.j2
	python3 $^ > $@

#gitlab-local: $(patsubst %,$(s)%.yml,$(GITLAB_SECTIONS))
gitlab-local: .gitlab-ci.yml

VPYTHON = VIRTUAL_ENV=$(1) PATH="$(1)/bin:$$PATH" $(1)/bin/python3
VPIP = VIRTUAL_ENV=$(1) PATH="$(1)/bin:$$PATH" $(1)/bin/pip3
VRUN = VIRTUAL_ENV=$(1) PATH="$(1)/bin:$$PATH" $(2)

GITLAB_VENV := $(o)venv
$(GITLAB_VENV): INSTALL_PACKAGES := jinja2 pyaml

%/venv:
	python3 -m venv $@
	$(call VPIP,$@) install $(INSTALL_PACKAGES)

gitlab-venv: $(GITLAB_VENV)
	$(call VRUN,$<,$(MAKE)) gitlab-local

gitlab-clean: s := $(s)
gitlab-clean:
	rm $(s)*.yml

clean::
	rm -rf $(GITLAB_VENV)

.PHONY: gitlab-local gitlab-venv gitlab-clean
