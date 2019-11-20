FROM i386/debian:wheezy-slim
ENV DEBIAN_FRONTEND noninteractive
RUN sed -i 'http://archive.debian.org/debian/'
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev
