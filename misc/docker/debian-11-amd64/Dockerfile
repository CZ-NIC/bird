FROM amd64/debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/deb.debian.org/ftp.cz.debian.org/' /etc/apt/sources.list
RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install \
	autoconf \
	build-essential \
	flex \
	bison \
	ncurses-dev \
	libreadline-dev

