# Gitlab CI tests
#GITLAB_SECTIONS := template

#$(s)%.yml: $(s)pipeline.py $(s)%.yml.j2 $(s)data.yml.j2
.gitlab-ci.yml: $(s)pipeline.py $(s)template.yml.j2 $(s)data.yml.j2
	python3 $^ > $@
	@if grep -n '	' $@; then echo "Found a tab in yaml output!"; false; fi

#gitlab-local: $(patsubst %,$(s)%.yml,$(GITLAB_SECTIONS))
gitlab-local: .gitlab-ci.yml

# Conditionally include Dockerfile build but only if required
ifneq ($(filter gitlab-docker $(s)docker,$(MAKECMDGOALS)),)
$(s)docker/%/Dockerfile: $(s)pipeline.py $(s)Dockerfile.j2 $(s)data.yml.j2
	$(if $(VENV),$(MAKE) $(GITLAB_VENV))
	mkdir -p $(dir $@)
	$(if $(VENV),$(call VPYTHON,$(GITLAB_VENV)),python3) $^ target=$* > $@

$(s)docker.mk: $(s)pipeline.py $(s)docker.mk.j2 $(s)data.yml.j2
	$(if $(VENV),$(MAKE) $(GITLAB_VENV))
	$(if $(VENV),$(call VPYTHON,$(GITLAB_VENV)),python3) $^ > $@

include $(s)docker.mk
endif

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
