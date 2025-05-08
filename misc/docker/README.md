# Docker files for our test machinery

**These files are not distribution files for running BIRD. We currently
do not supply official BIRD images and do not prepare any Docker files ourselves.**

We build for the major Linux distributions, FreeBSD and OpenBSD. If you feel
that your favourite Linux distribution is missing, feel free to send a patch.

Where to add your favourite Linux distribution:

- add an appropriate dockerfile here
- add `docker-*` job in `.gitlab-ci.yml`
- add `build-*` job in `.gitlab-ci.yml`
- add `pkg-*` job in `.gitlab-ci.yml`

Our build machinery needs at least Python 3.6 because of `beautifulsoup4`.
There is a hack for older distributions, installing an older version of
that dependency which works also with an older Python.

## Debian-based distributions

We support Debian between oldoldstable and testing. If not, poke us.

We support Ubuntu LTS at least 5 years old and non-LTS before EOL. After EOL,
the non-LTS package repositories tend to disappear quite quickly so we don't
have resources to build against.

## RedHat-based distributions

We support OpenSUSE, Fedora and CentOS. If you are missing your favourite new
release, poke us. We are discontinuing the old releases as they stop working.

The current support for CentOS 7 and 8 has been paid for and we may drop it without
further notice at the exact moment the customer stops using it.

## Any other based distributions

We currently don't package for Arch or Gentoo. Contributions are open, please
refer to `CONTRIBUTING.md` for further information.

You may also need to send a patch to [APKG](https://gitlab.nic.cz/packaging/apkg)
to facilitate the package building. Yet, if you wish to just test and check
builds without packaging, feel free to send the patch anyway.

## FreeBSD and OpenBSD

These are not built in Docker but in proper virtuals in QEMU, refer to
<https://gitlab.nic.cz/labs/bird-tools/-/tree/master/birdlab-tmp>
