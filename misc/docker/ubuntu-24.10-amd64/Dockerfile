# bump this to refresh the image: 1
FROM ubuntu:24.10
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
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
RUN apt-get -y install \
	git \
	dpkg-dev \
	debhelper \
	apt-utils \
	quilt \
	python3 \
	python3-pip \
	python3-setuptools
