FROM fedora:35
RUN dnf -y upgrade
#RUN dnf -y update
RUN dnf -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	# pkgconfig \
	# 'readline-devel' \
	# 'pkgconfig(ncurses)' \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN dnf -y install \
	git \
	rpm-build \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
