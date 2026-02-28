# Status dump
CONFIGURE_STATUS = $(if $(wildcard $(BUILDDIR)/config.status),,not configured)
BUILDDIR_EXISTS := $(wildcard $(BUILDDIR))

status:
	@echo "Selected build profile:       $(TARGET)"
	@echo "Source directory:             $(srcdir)"
	@echo "Object directory:             $(objdir)"
	@echo "Executable directory:         $(exedir)"
	@echo "Build directory:              $(BUILDDIR)$(if $(BUILDDIR_EXISTS),, (not created yet))"
	@echo "Configure arguments:          $(CONFARGS)"
	@echo "Default goal:                 $(.DEFAULT_GOAL)"
	@echo "Available profiles:           $(patsubst mk/target-%.mk,%,$(wildcard mk/target-*.mk))"
	@if [ -f $(BUILDDIR)/config.status ]; then \
		sed -nr '/config.status:[0-9]+: creating Makefile/,$${s#^configure:[0-9]+: result: ##p}' $(BUILDDIR)/config.log; \
	else \
		echo; echo "BIRD has not yet been configured, run make prepare"; \
	fi

# Help dump
help: mk/help.txt
	@cat $<

# Add to NOTARGETGOALS in common.mk because of late inclusion of this file!
.PHONY: help status
