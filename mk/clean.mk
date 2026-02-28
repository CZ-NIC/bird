# Clean targets
clean::
	rm -rf $(BUILDDIR)

distclean::

CLEANGOALS := clean distclean
NOTARGETGOALS += $(CLEANGOALS)
.PHONY: $(CLEANGOALS)
