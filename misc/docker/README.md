# Docker files for our test machinery

**These files are not distribution files for running BIRD. We currently
do not supply official BIRD images and do not prepare any Docker files ourselves.**

We build for the major Linux distributions, FreeBSD and OpenBSD. If you feel
that your favourite Linux distribution is missing, please send a patch.

Where to add your favourite Linux distribution:

- add an appropriate dockerfile here
- possibly add `pkg-*` and `install-*` template job in `misc/gitlab/template.yml.j2`
- add your distribution into the `distros` list in `misc/gitlab/data.yml.j2`
- run `make gitlab-local` or `make gitlab-venv` to rebuild `.gitlab-ci.yml`

## Debian-based distributions

We support Debian between oldoldstable and testing. If not, poke us.

We support Ubuntu LTS at least 5 years old and non-LTS before EOL. After EOL,
the non-LTS package repositories tend to disappear quite quickly so we don't
have resources to build against.

## RedHat-based distributions

We support OpenSUSE, Fedora, CentOS 7+8, Rocky Linux and Oracle Linux. If you are
missing your favourite new release, poke us. We are discontinuing the old
releases as they stop working.

The current support for CentOS 7 and 8 has been paid for and we may drop it without
further notice at the exact moment the customer stops using it.

We failed to find a reliable Docker image for Rocky Linux 10.

## Any other based distributions

We currently don't package for e.g. Alpine, Arch, Gentoo, Mint or Slackware.
Contributions are open, please refer to `CONTRIBUTING.md` for further information.

## FreeBSD and OpenBSD

These are not built in Docker but in proper virtuals in QEMU, refer to
<https://gitlab.nic.cz/labs/bird-tools/-/tree/master/birdlab-tmp>
