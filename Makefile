# Makefile for the BIRD Internet Routing Daemon
#
# (c) 2026       Maria Matejka <mq@jmq.cz>

# Default target is debug for Git builds, release for TGZ builds.
DEFAULT_TARGET := debug

# Released version. Empty in git builds, resolved in mk/build.mk later.
VERSION :=

# Set the build target
ifeq ($(TARGET),)
	TARGET := $(T)
endif
ifeq ($(TARGET),)
	TARGET := $(DEFAULT_TARGET)
endif

# Load appropriate defaults
include mk/target-$(TARGET).mk

$(info INFO Build profile is $(TARGET))

# Set the config var
CONFARGS ?= $(DEFAULT_CONFARGS)

# Set the build dir
BUILDDIR ?= $(DEFAULT_BUILDDIR)
ifeq ($(BUILDDIR),.)
	$(error Building with BUILDDIR=. is not supported.)
endif

srcdir := .

# Load auxiliary functions
include mk/common.mk

# Load our help
include mk/help.mk

# Load packaging
include mk/pkg.mk

# Load miscellaneous auxiliary goals
include mk/misc.mk

# Load autoconf goals
include mk/autoconf.mk

# Prepare the actual target's Makefile
$(BUILDDIR)/Makefile: configure Makefile.in mk/target-$(TARGET).mk
	mkdir -p $(BUILDDIR)
	cd $(BUILDDIR) && $(CWD)/configure $(CONFARGS)

reconf:
	rm -rf $(BUILDDIR)
	$(MAKE) $(BUILDDIR)/Makefile

NOTARGETGOALS += reconf
.PHONY: reconf

# Do we actually want to configure and load all the builds?
# - no configure for bash completion
# - no configure if only making NOTARGETGOALS
# - yes configure if default target
REAL_BUILD = $(strip \
	     $(if $(__BASH_MAKE_COMPLETION__),,\
	     $(if $(MAKECMDGOALS),$(filter-out $(NOTARGETGOALS),$(MAKECMDGOALS)),.DEFAULT)))

# Load the target Makefile if there is at least one target-specific goal
ifneq ($(REAL_BUILD),)
-include $(BUILDDIR)/Makefile
include mk/build.mk
include mk/test.mk
include mk/install.mk
else
all daemon cli prepare tags cscope test tests tests_run testsclean check static-scan install install-docs:
	@echo "If you see this message, there is a bug in the make machinery." > &2
	@echo "The goal $@ probably shouldn't be specified in NOTARGETGOALS:" > &2
	@echo "  NOTARGETGOALS = $(NOTARGETGOALS)" > &2
	@false
endif

# Finally load the clean targets
clean::
	rm -rf build

distclean:: clean
	rm -f configure sysdep/autoconf.h.in
