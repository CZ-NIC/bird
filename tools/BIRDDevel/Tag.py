import logging

from .Common import ReleaseException
from .Gitlab import gitlab, GitlabException
from .Command import Command, CommandError

logger = logging.getLogger(__name__)

class Tag:
    seen = {}

    def __new__(cls, name, data=None):
        if data is not None:
            assert(str(name) not in cls.seen)

        try:
            return cls.seen[str(name)]
        except KeyError:
            logger.debug(f"Tag {name} not yet checked")
            return super(Tag, cls).__new__(cls)

    def __init__(self, name, data=None):
        try:
            assert(Tag.seen[str(name)] == self)
            return
        except KeyError:
            pass

        self.name = name
        Tag.seen[str(name)] = self

        local, _ = Command("git", "tag", "-l", str(name))
        if local.strip() == str(name):
            lochash, _ = Command("git", "rev-parse", str(name))
            self.local = lochash.strip()
        else:
            self.local = None

        if data is None:
            try:
                data = gitlab.get(f"repository/tags/{str(name)}")
                self.parse_info(data)
            except GitlabException as e:
                self.remote = None
        else:
            self.parse_info(data)

    @classmethod
    def load(cls, **kwargs):
        data = gitlab.get_all(f"repository/tags", **kwargs)
        return { d['name']: cls(d['name'], data=d) for d in data }

    def parse_info(self, data):
        self.tag_sha = data['target']
        self.commit_sha = data['commit']['id']
        if \
                self.name[0] != "v" or \
                "alpha" in self.name or \
                "pre" in self.name:
            self.version = None
        else:
            self.version = Version(self.name[1:])

    def __getattr__(self, key):
        if key == "pipelines":
            self.pipelines = Pipeline.load(sha=self.commit_sha)
            return self.pipelines
        else:
            raise AttributeError(f"No attribute {key} in Tag")

    def __repr__(self):
        return f"Tag({str(self)})"

    def __str__(self):
        return f"self.name"

from .Pipeline import Pipeline
from .Version import Version
