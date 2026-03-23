# bump number for image rebuild: 0
FROM opensuse/leap:16.0
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
	lsb-release \
	rpm-build \
	libfaketime \
	systemd \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools \
	sysuser-tools
