# Makefile for the BIRD Internet Routing Daemon
#
# (c) 2026       Maria Matejka <mq@jmq.cz>
# (c) 2026       CZ.NIC, z.s.p.o.

# Released version. Empty in git builds, resolved in mk/build.mk later.
VERSION :=

# Hack for calling from outside
SOURCEDIR ?= .

# Default build target.
DEFAULT_TARGET := local

# Set the actual build target
ifeq ($(TARGET),)
	TARGET := $(T)
endif
ifeq ($(TARGET),)
	TARGET := $(DEFAULT_TARGET)
endif

ifneq ($(TARGET),$(subst /,!,$(TARGET)))
$(error Invalid target $(TARGET))
endif

ifeq ($(wildcard $(SOURCEDIR)/mk/target-$(TARGET).mk),)
$(error Unknown target $(TARGET), create one in file mk/target-$(TARGET).mk)
endif

# Auxiliary functions
include $(SOURCEDIR)/mk/common.mk

# Cleanup goals
include $(SOURCEDIR)/mk/clean.mk

# Packaging
include $(SOURCEDIR)/mk/pkg.mk

# Autoconf goals
include $(SOURCEDIR)/mk/autoconf.mk

# Load appropriate defaults
include $(SOURCEDIR)/mk/target-$(TARGET).mk

# Set the config args
CONFARGS ?= $(DEFAULT_CONFARGS)
CONFARGS += $(CONFARGS_EXTRA)

# Set the build dir
BUILDDIR ?= $(DEFAULT_BUILDDIR)
BUILDDIR ?= .
ifeq ($(realpath $(BUILDDIR)),$(realpath $(SOURCEDIR)))
$(error Building with BUILDDIR same as SOURCEDIR is not supported to keep the source directory clean.)
endif

# Gitlab CI updater
include $(SOURCEDIR)/mk/gitlab.mk

srcdir := .

# Do we actually want to configure and load all the builds?
# - no configure for bash completion
# - no configure if only making NOTARGETGOALS
# - yes configure if default target
REAL_BUILD = $(strip \
	     $(if $(__BASH_MAKE_COMPLETION__),,\
	     $(if $(MAKECMDGOALS),$(filter-out $(NOTARGETGOALS),$(MAKECMDGOALS)),.DEFAULT)))

ifneq ($(REAL_BUILD),)

$(info INFO Build profile is $(TARGET))

include $(BUILDDIR)/vars.mk
include $(SOURCEDIR)/mk/build.mk
include $(SOURCEDIR)/mk/test.mk
include $(SOURCEDIR)/mk/install.mk

else

ifneq ($(wildcard $(BUILDDIR)/vars.mk),)
include $(BUILDDIR)/vars.mk
endif

endif

# Load our help; this must be at the end for the status commands to work
include $(SOURCEDIR)/mk/help.mk
