# bump this to recreate the image: 4
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	build-essential \
	clang \
	clang-tools \
	flex \
	bison \
	autoconf \
	git \
	ncurses-dev \
	libreadline-dev \
	libssh-dev

RUN apt-get -y --no-install-recommends install pipx
RUN pipx install codechecker --global
