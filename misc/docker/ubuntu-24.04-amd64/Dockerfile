# bump this to refresh the image: 1
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	tzdata \
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
	apt-utils \
	quilt \
	python3 \
	python3-pip \
	python3-setuptools \
	python3-venv
