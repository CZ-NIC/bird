FROM debian:wheezy-slim
ENV DEBIAN_FRONTEND noninteractive
RUN sed -i 's/deb.debian.org/http:\/\/archive.debian.org\/debian\//' /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev
