FROM fedora:33

RUN dnf -y update  && dnf -y upgrade
RUN dnf -y install \
        make \
        autoconf \
        flex \
        bison \
        pkgconfig \
        "readline-devel" \
        "pkgconfig(ncurses)" \
        gcc

