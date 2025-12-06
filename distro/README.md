# BIRD upstream packaging sources

This distro/ directory contains packaging sources initially copied from Debian
and Fedora downstream repos. The team then updated these files for internal
integration testing and upstream repository builds.

## Create (source) package from current repo commit

Run `tools/make-archive` or `make archive` to create TGZ.

Run `tools/make-deb` or `tools/make-rpm` or `make deb` or `make rpm` to create
DEBs and/or RPMs for the current system.
