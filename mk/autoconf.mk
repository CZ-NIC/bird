# Targets for Autoconf
$(SOURCEDIR)/configure: $(SOURCEDIR)/aclocal.m4 $(SOURCEDIR)/configure.ac
	$(E)echo AUTORECONF
	$(Q)cd $(SOURCEDIR) && autoreconf

autoconf-clean:
	rm -rf autom4te*cache configure sysdep/autoconf.h.in

distclean:: autoconf-clean

NOTARGETGOALS += $(SOURCEDIR)/configure autoconf-clean
.PHONY: autoconf-clean
