# bump number for image rebuild: 0
FROM opensuse/leap:15.5
RUN zypper -n up
RUN zypper -n install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	pkgconfig \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN zypper -n install \
	git \
	rpm-build \
	systemd \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
