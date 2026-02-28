# Disable built-in rules
MAKEFLAGS += -r

# List goals which don't trigger including the target's generated Makefile
NOTARGETGOALS := clean distclean

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
