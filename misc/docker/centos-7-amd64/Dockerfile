# bump number for image rebuild: 0
FROM centos:7

# Has to be done for yum to work properly. CentOS 7 is EOL.
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo

# Add new repos for devtoolset-8-gcc.
# We need to use devtoolset, because BIRD cannot be correctly compiled with CentOS 7 version of gcc.
RUN echo -e \
	"\n[centos-sclo-rh]\nname=CentOS-7.8.2003 - SCLo rh\nbaseurl=https://vault.centos.org/7.8.2003/sclo/\$basearch/rh/\ngpgcheck=0\nenabled=1" \
	>> /etc/yum.repos.d/CentOS-Base.repo
RUN echo -e \
	"\n[centos-sclo-sclo]\nname=CentOS-7.8.2003 - SCLo sclo\nbaseurl=https://vault.centos.org/7.8.2003/sclo/\$basearch/sclo/\ngpgcheck=0\nenabled=1" \
	>> /etc/yum.repos.d/CentOS-Base.repo

RUN yum -y upgrade

# Change kernel-headers
RUN yum -y remove \
	kernel-headers
RUN yum -y install \
	https://dl.lamp.sh/kernel/el7/kernel-ml-headers-6.6.41-1.el7.x86_64.rpm

RUN yum -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	libssh-devel \
	ncurses-devel \
	readline-devel \
	centos-release-scl

RUN yum -y install \
	git \
	rpm-build \
	faketime \
	redhat-lsb-core \
	python3 \
	python3-pip \
	python3-setuptools \
	devtoolset-8-toolchain

# Backported newer RPM macros, hoping that it stays there for some while until we drop CentOS 7 support
RUN yum -y install \
	ftp://ftp.icm.edu.pl/packages/linux-pbone/ftp5.gwdg.de/pub/opensuse/repositories/systemsmanagement:/Ardana:/8:/CentOS/CentOS_7.3/noarch/systemd-rpm-macros-3-5.2.noarch.rpm
