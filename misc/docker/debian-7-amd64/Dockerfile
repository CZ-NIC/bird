FROM debian:wheezy-slim
ENV DEBIAN_FRONTEND noninteractive
RUN cat /etc/apt/sources.list
RUN echo 'deb http://archive.debian.org/debian/dists/wheezy/ wheezy main' > /etc/apt/sources.list
RUN echo 'deb http://archive.debian.org/debian/dists/wheezy/ wheezy-updates main' >> /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev
