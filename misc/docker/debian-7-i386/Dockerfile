FROM i386/debian:wheezy-slim
ENV DEBIAN_FRONTEND noninteractive
RUN echo 'http://archive.debian.org/debian/dists/wheezy/' > /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev
