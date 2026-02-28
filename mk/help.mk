# Status dump
CONFIGURE_STATUS = $(if $(wildcard $(BUILDDIR)/config.status),,not configured)

status:
	@echo "Selected build profile:       $(TARGET)"
	@echo "Executable path:              $(BUILDDIR)"
	@echo "Configure arguments:          $(CONFARGS)"
	@echo "Default goal:                 $(.DEFAULT_GOAL)"
	@echo "Available profiles:           $(patsubst mk/target-%.mk,%,$(wildcard mk/target-*.mk))"
	@if [ -f $(BUILDDIR)/config.status ]; then \
		sed -nr '/config.status:[0-9]+: creating Makefile/,$${s#^configure:[0-9]+: result: ##p}' $(BUILDDIR)/config.log; \
	else \
		echo; echo "BIRD has not yet been configured, run make reconf"; \
	fi

# Help dump
help:
	@echo "============================= BIRD make system ============================="
	@echo
	@echo "Source build options:"
	@echo "    make all                  Build BIRD binaries."
	@echo "    make test                 Build and run unit tests."
	@echo "    make docs                 Build documentation."
	@echo
	@echo "This build system supports -j parallelism. Feel free to use multiple cores."
	@echo
	@echo "Make variable-arguments:"
	@echo "    make T=profile            Select given build profile"
	@echo "                              Profiles are stored in mk/target-*.mk"
	@echo "    make V=1                  Verbose build output (no pretty-print)"
	@echo "    make C=1                  Colored build output even through pipe"
	@echo
	@echo "Partial build options:"
	@echo "    make path/to/foo.o        Build an object file, don't link."
	@echo "    make path/to/foo.E        Run only the C preprocessor."
	@echo "    make path/to/foo.S        Generate an assembler dump."
	@echo
	@echo "Development tools:"
	@echo "    make static-scan          Run CLang static analyzer."
	@echo "    make tags                 Generate ETags cache."
	@echo "    make cscope               Generate CScope cache."
	@echo
	@echo "Auxiliary commands:"
	@echo "    make help                 Show this help."
	@echo "    make status               Show information about current build."
	@echo "    make clean                Delete the build directory."
	@echo "    make distclean            Delete the build directory and configure script."
	@echo "    make gitlab-local         Re-generate .gitlab-ci.yml without venv"
	@echo "    make gitlab-venv          Re-generate .gitlab-ci.yml inside a tmp venv"
	@echo
	@echo "Distribution commands:"
	@echo "    make install              Install binaries into the system."
	@echo "    make archive              Create a release archive (TGZ)."
	@echo "                              This must exist for 'make deb' and 'make rpm'."
	@echo "    make deb                  Create a DEB package for the current system."
	@echo "    make rpm                  Create an RPM package for the current system."

NOTARGETGOALS += help status
.PHONY: help status
