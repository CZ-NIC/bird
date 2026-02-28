# Where to put object files
DEFAULT_BUILDDIR := build/local

# Re-use previous configure args if exist
ifneq ($(REAL_BUILD),)
-include $(DEFAULT_BUILDDIR)/vars.mk
else
ifneq ($(wildcard $(DEFAULT_BUILDDIR)/vars.mk),)
include $(DEFAULT_BUILDDIR)/vars.mk
endif
endif

DEFAULT_CONFARGS := $(ACTUAL_CONFARGS)

.DEFAULT_GOAL := all
