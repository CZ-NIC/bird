FROM i386/debian:stretch-slim
ENV DEBIAN_FRONTEND noninteractive

# Has to be done for apt-get to work properly. Debian 9 is EOL.
RUN sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list
RUN sed -i 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list 
RUN sed -i '/stretch-updates/d' /etc/apt/sources.list

RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	build-essential \
	flex \
	bison \
	autoconf \
	ncurses-dev \
	libreadline-dev \
	libssh-gcrypt-dev \
	linuxdoc-tools-latex \
	texlive-latex-extra \
	opensp \
	docbook-xsl \
	xsltproc
RUN apt-get -y --no-install-recommends install \
	git \
	dpkg-dev \
	debhelper \
	quilt \
	python3 \
	python3-pip \
	python3-setuptools
