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
