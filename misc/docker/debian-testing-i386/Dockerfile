FROM i386/debian:testing-slim
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install \
	build-essential \
	flex \
	bison \
	autoconf \
	ncurses-dev \
	libreadline-dev
