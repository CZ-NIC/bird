# bump number for image rebuild: 1
# check latest supported version at https://wiki.rockylinux.org/rocky/version/#__tabbed_1_2
FROM oraclelinux:10

RUN dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm

RUN yum -y upgrade
RUN yum -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN yum -y install \
	git \
	lsb-release \
	rpm-build \
	faketime \
	systemd \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
