import os
import pathlib
import sys

from .Common import ReleaseException
from .Command import Command, CommandError
from .Version import Version

# A singleton class accessing the current git state
class Git:
    def __init__(self):
        # Normalize where we are
        self.toplevel = pathlib.Path(sys.argv[0]).parent.parent.absolute()
        os.chdir(self.toplevel)

        with open("VERSION", "r") as f:
            self.version = Version(f.read().strip())

        try:
            gitbranch = [ x[3:] for x in Command("git", "status", "-bs") if x.startswith("## ") ][0]
        except Exception as e:
            raise ReleaseException(f"Git status is broken, are you even inside a repo?") from e

        if "(no branch)" in gitbranch:
            raise ReleaseException(f"Not on any branch, I refuse to release.")

        if "..." not in gitbranch and " " not in gitbranch:
            raise ReleaseException(f"Detected branch {gitbranch} but not tracking any remote. I refuse to release.")

        try:
            locbranch, remref = gitbranch.split("...")
            remote, rembranch = remref.split("/")
            remuri, _ = Command("git", "remote", "get-url", remote)
        except Exception as e:
            raise ReleaseException(f"This does not look like a regular branch, git status says: {gitbranch}") from e

        if \
                "https" not in remuri and "git@" not in remuri \
                or "gitlab.nic.cz" not in remuri \
                or "labs/bird" not in remuri \
                or "office" in remuri:
                    raise ReleaseException(f"Current branch is {locbranch}, tracking {rembranch} at {remote} but the appropriate uri is kinda sus: {remuri}")


#        if locbranch != rembranch:
#            raise ReleaseException(f"Hey sis, your local branch {locbranch} tracks remote branch {rembranch} at {remote}. Go and fix that mess.")

        self.remote = remote
        self.branch = locbranch

    def __str__(self):
        return f"Git(toplevel={self.toplevel},branch={self.branch},version={self.version})"

    def token(self):
        try:
            return self._token
        except AttributeError:
            try:
                self._token, _ = Command("git", "config", "gitlab.token")
                return self._token
            except CommandError as e:
                raise ReleaseException(f"To use gitlab API, you need a token. Add one in \"Settings → Access Tokens\" and call \"git config set --local gitlab.token=<token>\".") from e

git = Git()
