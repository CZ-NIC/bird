# bump number for image rebuild: 0
FROM centos:8

# Has to be done for yum to work properly. CentOS 8 is EOL.
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo

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
	rpm-build \
	redhat-lsb-core \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
