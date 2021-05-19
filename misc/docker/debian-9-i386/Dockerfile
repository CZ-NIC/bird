FROM i386/debian:stretch-slim
ENV DEBIAN_FRONTEND noninteractive
RUN sed -i 's/deb.debian.org/ftp.cz.debian.org/' /etc/apt/sources.list
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
