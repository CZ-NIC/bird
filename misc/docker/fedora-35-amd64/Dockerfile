FROM fedora:35
RUN dnf -y upgrade
RUN dnf -y install \
	make \
	autoconf \
	flex \
	bison \
	pkgconfig \
	'readline-devel' \
	'pkgconfig(ncurses)' \
	gcc
