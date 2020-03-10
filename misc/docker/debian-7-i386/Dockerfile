FROM i386/debian:wheezy-slim
ENV DEBIAN_FRONTEND noninteractive
RUN echo 'deb http://archive.debian.org/debian/ wheezy main' > /etc/apt/sources.list
RUN echo 'deb http://archive.debian.org/debian-security/ wheezy/updates main' >> /etc/apt/sources.list
RUN apt-get -y update -o Acquire::Check-Valid-Until=false
RUN apt-get -y upgrade
RUN apt-get --no-install-recommends install -y \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev
