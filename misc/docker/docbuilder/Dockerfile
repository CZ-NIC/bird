# bump this to recreate the image: 2
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	build-essential \
	flex \
	bison \
	autoconf \
	git \
	pandoc \
	ncurses-dev \
	libreadline-dev \
	libssh-gcrypt-dev \
	linuxdoc-tools-latex \
	texlive-latex-extra \
	groff \
	opensp \
	docbook-xsl \
	xsltproc
RUN apt-get -y --no-install-recommends install \
	dpkg-dev \
	debhelper \
	apt-utils \
	quilt \
	python3 \
	python3-pip \
	python3-setuptools \
	python3-venv
