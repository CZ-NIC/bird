# bump number for image rebuild: 0
FROM fedora:32
RUN dnf -y upgrade
RUN dnf -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	pkgconfig \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN dnf -y install \
	git \
	redhat-lsb-core \
	rpm-build \
	faketime \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
