# Disable build-in rules
MAKEFLAGS += -r

# List goals which don't trigger including the target's generated Makefile.
# This includes goals from help.mk so that it can be included late.
NOTARGETGOALS := help status

# List goals needed for status info
STATUSGOALS := status status-%

# Set Make output verbosity
VERBOSE ?= $(V)
ifeq ($(VERBOSE),)
  E:=@
  Q:=@
else
  E:=@\#
  Q:=
endif

# Force colored output if requested
COLOR ?= $(C)
ifneq ($(COLOR),)
  CFLAGS += -fdiagnostics-color=always
endif

# Store where we actualy are
CWD := $(shell pwd)

# List directories always included
subdirs := client conf doc filter lib nest test

# Meta-goals
all-with-test: test all
all-with-docs: docs test all
.PHONY: all-with-docs all-with-test
