# Packaging and releasing script wrapper
archive:
	tools/make-archive

deb:
	tools/make-deb

rpm:
	tools/make-rpm

NOTARGETGOALS += archive deb rpm
.PHONY: archive deb rpm
