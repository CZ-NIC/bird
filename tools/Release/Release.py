import logging

from .Common import ReleaseException
from .Command import Command, CommandError
from .Git import git
from .Milestone import Milestone
from .Issue import ReleaseChecklistIssue

logger = logging.getLogger(__name__)

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

    def create_branch(self):
        name = f"release-v{self.version}"
        logger.info(f"Creating branch {name}")
        try:
            Command("git", "checkout", "-b", name)
        except CommandError as e:
            raise ReleaseException(f"Failed to create branch {name}") from e

    def dispatch(self, args):
        m = {
                "info": self.info,
                "prepare": self.prepare,
                }
        try:
            c = m[args[0]]
        except IndexError:
            logger.error(f"No command supplied.")
            logger.info(f"Available commands: {', '.join(m.keys())}")
            return
        except KeyError:
            logger.error(f"Unknown command {args[0]}.")
            logger.info(f"Available commands: {', '.join(m.keys())}")
            return

        return c(*args[1:])

    def info(self):
        logger.info(f"Would release {self.kind} version {self.version} from branch {git.branch}")

        # Print milestone info
        for t,m in self.milestones().items():
            if m.exists:
                logger.info(f"Milestone v{m.version} ({t}) exists: {m.url}")
            else:
                logger.info(f"Milestone v{m.version} ({t}) missing")

        # Print issue info
        if (issue := ReleaseChecklistIssue(self)).exists:
            logger.info(f"Release issue #{issue.local_id} exists: {issue.url}")
        else:
            logger.info(f"Release issue missing.")

    def prepare(self):
        logger.info(f"Releasing {self.kind} version {self.version} from branch {git.branch}")

        # Check commit history
        try:
            assert(Command("tools/git-check-commits") == [""])
        except Exception as e:
            raise ReleaseException("Commit structure unsuitable for release!") from e

# Not creating release branch, maybe later
#        if not git.branch.startswith("release-v"):
#            self.create_branch()

        # Assure milestones exist
        for t,m in self.milestones().items():
            if m.exists:
                logger.info(f"Milestone v{m.version} ({t}) already exists: {m.url}")
            else:
                m.create()
                logger.info(f"Created milestone v{m.version} ({t}): {m.url}")

        # Assure issue exists
        if (issue := ReleaseChecklistIssue(self)).exists:
            logger.info(f"Release issue #{issue.local_id} already exists: {issue.url}")
        else:
            issue = ReleaseChecklistIssue.create(self)
            logger.info(f"Release issue #{issue.local_id} created: {issue.url}")


# Subclasses to define things where Minor and Patch release actually differ
class MinorRelease(Release):
    kind = "minor"

    def milestones(self):
        return {
                "this": Milestone(self.version), # The version we are currently releasing
                "next": Milestone(self.version.next_minor()), # What didn't make it
                "patch": Milestone(self.version.next_patch()), # Fixes of this version
                }

    def issue_template_data(self):
        return {
                "this": self.version.template_data(),
                "next": self.version.next_minor().template_data(),
                "patch": self.version.next_patch().template_data(),
                }

class PatchRelease(Release):
    kind = "patch"

    def milestones(self):
        return {
                "this": Milestone(self.version), # The version we are currently releasing
                "next": Milestone(self.version.next_patch()), # Fixes of this version
                "main": Milestone(self.version.next_minor()), # What actually isn't a bug worth patchfixing
                }

    def issue_template_data(self):
        return {
                "this": self.version.template_data(),
                "next": self.version.next_patch().template_data(),
                "main": self.version.next_minor().template_data(),
                }
