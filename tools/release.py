#!/usr/bin/python3

import jinja2
import logging
import os
import pathlib
import requests
import subprocess
import sys

logging.basicConfig(format='%(levelname)# 8s | %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

class CommandError(Exception):
    def __str__(self):
        return f"""Command {self.args[0].args} failed with code {self.args[0].returncode}.
        {self.args[0].stdout.decode()}
        {self.args[0].stderr.decode()}"""

def cmd(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode != 0:
        raise CommandError(result)

    return result.stdout.decode().split("\n")

class ReleaseException(Exception):
    pass

class Version:
    def __init__(self, *args):
        if len(args) == 3:
            for a in args:
                assert(isinstance(a, int))
            
            self.major, self.minor, self.patch = tuple(args)

        else:
            assert(len(args) == 1)
            s = args[0].split('.')
            if len(s) > 3:
                raise ReleaseException(f"Weird version: {value} (too many dots)")

            try:
                self.major = int(s[0])
                self.minor = int(s[1])
            except Exception as e:
                raise ReleaseException(f"Weird version: {value}") from e

            try:
                self.patch = int(s[2])
            except IndexError:
                self.patch = 0
            except Exception as e:
                raise ReleaseException(f"Weird version: {value}") from e

        if self.major == 2 and self.patch == 0:
            self.branch = "master"
        elif self.major == 3 and self.patch == 0:
            self.branch = "thread-next"
        else:
            self.branch = f"stable-v{self.major}.{self.minor}"


    def __eq__(self, other):
        return self.major == other.major and self.minor == other.minor and self.patch == other.patch

    def __repr__(self):
        return f"Version({str(self)})"

    def __str__(self):
        if self.major == 2 and self.patch == 0:
            return f"{self.major}.{self.minor}"
        else:
            return f"{self.major}.{self.minor}.{self.patch}"

    def next_patch(self):
        return Version(self.major, self.minor, self.patch + 1)

    def next_minor(self):
        return Version(self.major, self.minor + 1, 0)

    def next_major(self):
        return Version(self.major + 1, 0, 0)

    def template_data(self):
        return {
                "version": str(self),
                "branch": {
                    "name": self.branch,
                    "url": "https://gitlab.nic.cz/labs/bird/-/commits/" + self.branch,
                    },
                "milestone": Milestone(self).template_data(),
                }

class Milestone:
    seen = {}

    def __new__(cls, version):
        try:
            return cls.seen[str(version)]
        except KeyError:
            logger.debug(f"Milestone v{version} not yet queried")
            return super(Milestone, cls).__new__(cls)

    def __init__(self, version):
        try:
            assert(Milestone.seen[str(version)] == self)
            return
        except KeyError:
            pass

        milestone = gitlab.get(f"milestones?title=v{version}")
        if len(milestone) == 0:
            milestone = gitlab.post(f"milestones", json={
                "title": f"v{version}",
                "description": f"Collection of issues intended to be resolved in release {version}",
                })
            logger.debug(f"Gitlab replied: {milestone}")
            logger.info(f"Created milestone v{version}: {milestone['web_url']}")
            self.id = milestone['iid']
            self.url = milestone['web_url']
            self.name = milestone['title']
            Milestone.seen[str(version)] = self

        elif len(milestone) == 1:
            logger.info(f"Milestone v{version} already exists: {milestone[0]['web_url']}")
            self.id = milestone[0]['iid']
            self.url = milestone[0]['web_url']
            self.name = milestone[0]['title']
            Milestone.seen[str(version)] = self
        else:
            raise ReleaseException(f"Too many milestones of name v{version}: {milestone}")

    def template_data(self):
        return {
                "name": self.name,
                "url": self.url,
                "id": self.id,
                }

# A singleton class accessing the current git state
class GitState:
    def __init__(self):
        # Normalize where we are
        self.toplevel = pathlib.Path(sys.argv[0]).parent.parent.absolute()
        os.chdir(self.toplevel)

        with open("VERSION", "r") as f:
            self.version = Version(f.read().strip())

        try:
            gitbranch = [ x[3:] for x in cmd("git", "status", "-bs") if x.startswith("## ") ][0]
        except Exception as e:
            raise ReleaseException(f"Git status is broken, are you even inside a repo?") from e

        if "(no branch)" in gitbranch:
            raise ReleaseException(f"Not on any branch, I refuse to release.")

        if "..." not in gitbranch and " " not in gitbranch:
            raise ReleaseException(f"Detected branch {gitbranch} but not tracking any remote. I refuse to release.")

        try:
            locbranch, remref = gitbranch.split("...")
            remote, rembranch = remref.split("/")
            remuri, _ = cmd("git", "remote", "get-url", remote)
        except Exception as e:
            raise ReleaseException(f"This does not look like a regular branch, git status says: {gitbranch}") from e

        if \
                "https" not in remuri and "git@" not in remuri \
                or "gitlab.nic.cz" not in remuri \
                or "labs/bird" not in remuri \
                or "office" in remuri:
                    raise ReleaseException(f"Current branch is {locbranch}, tracking {rembranch} at {remote} but the appropriate uri is kinda sus: {remuri}")


        if locbranch != rembranch:
            raise ReleaseException(f"Hey sis, your local branch {locbranch} tracks remote branch {rembranch} at {remote}. Go and fix that mess.")

        self.remote = remote
        self.branch = locbranch

    def __str__(self):
        return f"GitState(toplevel={self.toplevel},branch={self.branch},version={self.version})"

    def token(self):
        try:
            return self._token
        except AttributeError:
            try:
                self._token, _ = cmd("git", "config", "gitlab.token")
                return self._token
            except CommandError as e:
                raise ReleaseException(f"To use gitlab API, you need a token. Add one in \"Settings → Access Tokens\" and call \"git config set --local gitlab.token=<token>\".") from e


class GitlabException(Exception):
    def __str__(self):
        return f"Gitlab request {self.args[0]} failed with {self.args[1].status_code}"

# A singleton class providing raw Gitlab API
class Gitlab:
    stem = "https://gitlab.nic.cz/api/v4/projects/labs%2Fbird/"
    def get(self, uri):
        response = requests.get(self.stem + uri, headers={"PRIVATE-TOKEN": git.token()})
        if not response.ok:
            raise GitlabException(self.stem + uri, response)

        return response.json()

    def post(self, uri, **kwargs):
        response = requests.post(self.stem + uri, headers={"PRIVATE-TOKEN": git.token()}, **kwargs)
        if not response.ok:
            raise GitlabException({ "uri": self.stem + uri, **kwargs }, response)

        return response.json()

class Templater:
    def __init__(self):
        self.j2env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))

    def process(self, tpath, **data):
        te = self.j2env.get_template(tpath)
        return te.render(**data)

# A singleton class doing the release
class Release:
    def __new__(cls, *args, **kwargs):
        if cls != Release:
            return super(Release, cls).__new__(cls)

        version = None
        if git.branch == "master":
            cls = MinorRelease
            assert(git.version.major == 2)
            version = git.version.next_minor()

        elif git.branch == "thread-next":
            cls = MinorRelease
            assert(git.version.major == 3)
            version = git.version.next_minor()

        elif git.branch == f"stable-v{git.version.major}.{git.version.minor}":
            cls = PatchRelease
            version = git.version.next_patch()

        elif git.branch.startswith("release-v"):
            bv = git.branch[9:]
            nmi = git.version.next_minor()
            npa = git.version.next_patch()

            if Version(bv) == git.version:
                version = git.version
                cls = MinorRelease if git.version.patch == 0 else PatchRelease
            elif Version(bv) == nmi:
                version = nmi
                cls = MinorRelease
            elif Version(bv) == npa:
                version = npa
                cls = PatchRelease
            else:
                raise ReleaseException(f"Release branch {git.branch} incongruent with its VERSION {git.version}")
        else:
            raise ReleaseException(f"I have no idea what to release from branch {git.branch}")

        obj = cls.__new__(cls)
        obj.version = version
        return obj

    def __init__(self):
        logger.info(f"Releasing {self.kind} version {self.version} from branch {git.branch}")
        super().__init__()

    def issue(self):
        issue = gitlab.get(f"issues?labels=release-checklist&state=opened&milestone=v{self.version}")
        if len(issue) == 0:
            logger.info(f"Release issue does not exist yet, creating")
#            print({
            issue = gitlab.post(f"issues", json={
                "title": f"BIRD {self.version} release ({ self.kind })",
                "labels": f"release-{self.kind},release-checklist",
                "milestone_id": Milestone(self.version).id,
                "description": templater.process(
                    "tools/release-issue.md.j2",
                    **(self.issue_template_data()),
                    kind=self.kind,
                    )
                })
            logger.info(f"Check the release issue #{issue['iid']} at {issue['web_url']}")

        elif len(issue) == 1:
            logger.info(f"Release issue #{issue[0]['iid']} already exists: {issue[0]['web_url']}")
        else:
            raise ReleaseException(f"Too many release issues for version {version}: {[ i['web_url'] for i in issue].join(', ')}")


    def create_branch(self):
        name = f"release-v{self.version}"
        logger.info(f"Creating branch {name}")
        try:
            cmd("git", "checkout", "-b", name)
        except CommandError as e:
            raise ReleaseException(f"Failed to create branch {name}") from e

    def run(self):
        # Check commit history
        try:
            assert(cmd("tools/git-check-commits") == [""])
        except Exception as e:
            raise ReleaseException("Commit structure unsuitable for release!") from e

# Not creating release branch, maybe later
#        if not git.branch.startswith("release-v"):
#            self.create_branch()

        # Assure 
        self.milestones()
        self.issue()


# Subclasses to define things where Minor and Patch release actually differ
class MinorRelease(Release):
    kind = "minor"

    def milestones(self):
        Milestone(self.version) # The version we are currently releasing
        Milestone(self.version.next_minor()) # What didn't make it
        Milestone(self.version.next_patch()) # Fixes of this version

    def issue_template_data(self):
        return {
                "this": self.version.template_data(),
                "next": self.version.next_minor().template_data(),
                "patch": self.version.next_patch().template_data(),
                }

class PatchRelease(Release):
    kind = "patch"

    def milestones(self):
        Milestone(self.version) # The version we are currently releasing
        Milestone(self.version.next_minor()) # What actually isn't a bug worth patchfixing
        Milestone(self.version.next_patch()) # Fixes of this version

    def issue_template_data(self):
        return {
                "this": self.version.template_data(),
                "next": self.version.next_patch().template_data(),
                "main": self.version.next_minor().template_data(),
                }

# Do the release preparation
try:
    git = GitState()
    gitlab = Gitlab()
    templater = Templater()
    release = Release()
    release.run()
except ReleaseException as e:
    logger.error(e, exc_info=True)
except Exception:
    logger.exception("Fatal error", exc_info=True)
