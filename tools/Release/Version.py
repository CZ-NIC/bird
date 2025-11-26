from .Common import ReleaseException

class Version:
    """
    Object representing BIRD version.
    """
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
        """Calculate next patch version from this one"""
        return Version(self.major, self.minor, self.patch + 1)

    def next_minor(self):
        """Calculate next minor version from this one"""
        return Version(self.major, self.minor + 1, 0)

    def next_major(self):
        """Calculate next major version from this one"""
        return Version(self.major + 1, 0, 0)

    def template_data(self):
        """Return data for Jinja templating (TODO: make this nicer)"""
        return {
                "version": str(self),
                "branch": {
                    "name": self.branch,
                    "url": "https://gitlab.nic.cz/labs/bird/-/commits/" + self.branch,
                    },
                "milestone": Milestone(self).template_data(),
                }

from .Milestone import Milestone
