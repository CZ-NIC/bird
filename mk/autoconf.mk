# Targets for Autoconf
configure: aclocal.m4 configure.ac
	$(Q)autoreconf

reconfig: autoconf-clean
	rm configure
	$(MAKE) configure

autoconf-clean:
	rm -rf autom4te*cache

distclean:: autoconf-clean

NOTARGETGOALS += configure reconfig autoconf-clean
.PHONY: reconfig autoconf-clean
