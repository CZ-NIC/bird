# bump this to refresh the image: 1
<<<<<<<< HEAD:misc/docker/ubuntu-25.04-amd64/Dockerfile
FROM ubuntu:25.04
|||||||| parent of f88de9142 (CI: Update supported distributions):misc/docker/ubuntu-24.10-amd64/Dockerfile
FROM ubuntu:24.10
========
FROM ubuntu:25.10
>>>>>>>> f88de9142 (CI: Update supported distributions):misc/docker/ubuntu-25.10-amd64/Dockerfile
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
	libssh-dev \
	linuxdoc-tools-latex \
	texlive-latex-extra \
	opensp \
	docbook-xsl \
	xsltproc \
	adduser
RUN apt-get -y --no-install-recommends install \
	git \
	dpkg-dev \
	debhelper \
	lsb-release \
	apt-utils \
	quilt \
	python3 \
	python3-pip \
	python3-setuptools \
	python3-venv
