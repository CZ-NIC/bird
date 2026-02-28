# How to install BIRD

## Distribution packages

There are packages available via the packaging systems of most of the existing
distributions, and it is often a cleaner way to install BIRD than manually.
The upstream team also provides current packages for various DEB and RPM
distributions, all linked from our [download page](https://bird.nic.cz/get-bird/)

## Getting source code

Release tarballs are available at our [download page](https://bird.nic.cz/get-bird/).

It is also possible to clone Git. Released versions are tagged.

```sh
$ git clone https://gitlab.nic.cz/labs/bird
$ git checkout v2.20.0 # for the 2.20.0 release
```

## Build requirements

For compiling BIRD you need these programs and libraries:

 - GNU C Compiler (or LLVM Clang)
 - GNU Make
 - GNU Bison
 - GNU M4
 - Flex

 - ncurses library
 - GNU Readline library
 - libssh library (optional, for RPKI-Router protocol)

For compiling BIRD documentation you also need:

 - Linuxdoc-Tools
 - LaTeX

If building from Git you also need:

 - Git
 - GNU Autoconf

You may check our [internal build dockers](gitlab/docker/) for more precise package lists.

## Build process

You run make.

    $ make

This configures and builds binaries `bird`, `birdc` and `birdcl`. You may find them in
`build/local/` subfolder.

These binaries will run perfectly from wherever you put them. You can install
them to the system paths if you want:

    # make install

For debugging and development, it's recommended to use the `-l` flag for BIRD
binaries to use `bird.conf` and `bird.ctl` in the current directory, instead of
system-wide installation of an unstable version.

If you don't like reading our [documentation SGML](doc/bird.sgml) directly, you
may [check the website](https://bird.nic.cz/doc/latest/), or build documentation locally:

    $ make docs

If you run `./configure` before `make`, you may change the build configuration
options. To build from Git, you need to run:

    $ make configure && ./configure <options>

If you change `configure.ac` or `aclocal.m4`, your build gets auto-reconfigured
with the same arguments.

The `./configure` script has `--help`.

## Build profiles

You may choose different build profiles by setting `T=<profile>`, i.e.

    $ make T=release

Predefined are `debug` and `release` in `mk/target-*.mk`, and you can define
your own if needed, e.g. if you want to store your favourite `./configure` options.

To get more information about the build system:

    $ make help
