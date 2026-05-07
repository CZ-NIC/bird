# BIRD CI Pipelines

There is quite a lot to do during our CI to ensure that BIRD stays stable and
no regression is introduced by regular development. We do as much as possible
in an automated way so that routine tasks aren't botched by somebody missing
a step.

## Pipeline structure

The main [main `.gitlab-ci.yml` file](../../.gitlab-ci.yml) is double-templated.

Primary data is in [data.yml.j2](data.yml.j2) which is itself processed by
Jinja to expand various data structures.  The expanded data is then passed to
the templater, converting [template.yml.j2](template.yml.j2) to the final
target file.

The main file is committed into the repository, and therefore every change to
the source files must be accompanied with `make gitlab-local` (if you have
`jinja2` and `pyaml` installed locally) or `make gitlab-venv` which creates a
venv for that job on the fly. If that file was generated on the fly, it would
add some unnecessary half a minute to the CI run time, and make the CI output
more confusing.

We would love to split the main CI file to some nice smaller parts but it would
probably impose quite a lot of repetitive work because of Gitlab. At least
we can document these parts as separate chapters.

## Consistency

Release-worthy commits are put into specific branches. These are:

- `master` for BIRD 2
- `thread-next` for BIRD 3
- `stable-v*` for patch release branches

These branches require some commit hygiene, which is checked by the script
in `tools/git-check-commits`, and if anybody pushes a commit which fails the
consistency check, they should immediately force-push a fixed history.

Notably, this check requires all the commits to not be marked as `fixup!` or
as `WIP`, which both marks unfinished work.

TODO:

- add also check that the gitlab CI file is up-to-date with the sources

## Build tests

We have been historically hit by multiple integration problems arising from
distributions either keeping old tooling versions (e.g. old compilers),
breaking things by updates, or simply using different libraries and tools
than the core team which runs mostly Debian, Ubuntu and Fedora (as of 2026).

Therefore, we check builds for multiple distribution versions from last about
5-10 years, depending on customer requirements and actual possibility to get a
docker image for that distro.

We also run build tests for FreeBSD, OpenBSD and NetBSD inside QEMU. The images
are half-defined inside our
[temporary virtualization platform](https://gitlab.nic.cz/labs/bird-tools/-/tree/master/birdlab-tmp)
but please note that there are quite some updates local to the deployment, which
have not been applied back to that repository.

Last but not least, we check partial builds where some of the protocols are switched off.

TODO:

- commit changes for the virtualization platform and test deployment from scratch
- add partial builds checking other `configure` checks, e.g. presence of `libssh`
- add cross platform builds at least nightly

## Runtime tests

These tests use the [Netlab infrastructure](https://gitlab.nic.cz/labs/bird-tools/-/tree/master/netlab) (yes, another Netlab), and we gradually add more tests covering more
BIRD functionality. There are also regression tests included.

## Packaging and install tests

These tasks build BIRD packages for various Linux distributions, and check whether these
actually install cleanly.

TODO:

- add automated cross platform packaging
- add package signing and repo upload
- add alpine
- add production docker image build

## Tag build collection

Release helper to collect all built packages when tag is made.

## Internal docker rebuild

All the distro build and packaging is done in docker build environments,
prepared with all the build dependencies, to shorten build times.

TODO:

- add on-demand triggers from the gitlab web ui

# Docker files for our test machinery

**These files are not distribution files for running BIRD. We currently
do not supply official BIRD images and do not prepare any Docker files ourselves.**

We build for the major Linux distributions, FreeBSD and OpenBSD. If you feel
that your favourite Linux distribution is missing, please send a patch.

Where to add your favourite Linux distribution:

- add an appropriate dockerfile here
- possibly add `pkg-*` and `install-*` template job in `gitlab/template.yml.j2`
- add your distribution into the `distros` list in `gitlab/data.yml.j2`
- run `make gitlab-local` or `make gitlab-venv` to rebuild `.gitlab-ci.yml`

Rebuilding the docker images is done by triggering the appropriate pipeline manually in Gitlab.

When images are disused, check [the registry](https://gitlab.nic.cz/labs/bird/container_registry/)
and untag them so that they can be garbage-collected.

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
