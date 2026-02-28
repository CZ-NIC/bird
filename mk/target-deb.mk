# Build with full optimization.
DEFAULT_BUILDDIR := build/deb
DEFAULT_CONFARGS := \
	--prefix=/usr \
       	--sysconfdir=/etc/bird \
       	--mandir=\$${prefix}/share/man \
	--infodir=\$${prefix}/share/info \
	--localstatedir=/var \
	--runstatedir=/run/bird \
	--docdir=\$${prefix}/share/bird2 \
	--enable-client \
	--with-protocols=all \

all-with-docs: all check docs
.PHONY: all-with-docs

install: install-conf

.DEFAULT_GOAL := all-with-docs

VERBOSE := 1
