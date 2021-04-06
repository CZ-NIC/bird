# BIRD upstream packaging sources

This distro/ directory contains packaging sources initially copied from Debian
and Fedora downstream repos.

Files in this directory follow [apkg] conventions and apkg can be used to
create BIRD packages for various distros directly from upstream sources as
well as from upstream archives.

[apkg]: https://apkg.rtfd.io


## Create (source) package from current repo commit

Following command should build source package for current distro directly
from current repo state - run at top bird directory:

    apkg srcpkg

or build native packages directly:

    apkg build

or in case of disposable VM/container you can use faster direct host build

    apkg build -Hi

tools/make-dev-archive script is in charge of creating archive from source.


## Create (source) package from upstream release

Following commands can be used to clone upstream repo, download current upstream
archive (tarball), and build Debian, Ubuntu, Fedora, CentOS, or OpenSUSE
source package (depending on host system) using files in bird/distro:

    git clone https://gitlab.nic.cz/labs/bird
    cd bird
    apkg get-archive
    apkg srcpkg -a pkg/archives/upstream/bird-2.0.8.tar.gz

To create native packages instead use `build`:

    apkg build -a pkg/archives/upstream/bird-2.0.8.tar.gz

Or to build packages directly in case of a disposable VM/container (faster, modifies system):

    apkg build -Hi -a pkg/archives/upstream/bird-2.0.8.tar.gz


## Build packages in openSUSE Build Service (OBS)

tools/make-obs script can be used on Debian-based system to create OBS
source package in pkg/obs directory ready to be uploaded:

    cd bird
    apkg get-archive
    ./tools/make-obs
    # result in pkg/obs

You can also supply (upstream) archive to build from:

    # or to use specified archive
    ./tools/make-obs pkg/archives/upstream/bird-2.0.8.tar.gz


## More Info

Please see [apkg docs][apkg].
