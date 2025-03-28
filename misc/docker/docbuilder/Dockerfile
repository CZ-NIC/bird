FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y --no-install-recommends install \
	build-essential \
	flex \
	bison \
	autoconf \
	git \
	pandoc \
	linuxdoc-tools-latex \
	texlive-latex-extra \
	groff \
	opensp \
	docbook-xsl \
	xsltproc
