FROM fedora:34
RUN dnf -y upgrade
RUN dnf -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
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
