FROM debian:stretch-slim
ENV DEBIAN_FRONTEND noninteractive
RUN sed -i 's/deb.debian.org/ftp.cz.debian.org/' /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev \
	libssh-gcrypt-dev \
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
