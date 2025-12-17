import logging

from .Common import ReleaseException
from .Gitlab import gitlab

logger = logging.getLogger(__name__)


# Milestones should exist to versions
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

        self.version = version
        Milestone.seen[str(version)] = self

        milestone = gitlab.get(f"milestones?title=v{version}")

        if len(milestone) == 0:
            self.exists = False
        elif len(milestone) == 1:
            self.parse_info(milestone[0])
        else:
            raise ReleaseException(f"Too many milestones of name v{version}: {milestone}")

    def parse_info(self, data):
        self.exists = True
        self.local_id = data['iid']
        self.gitlab_id = data['id']
        self.url = data['web_url']
        self.name = data['title']
        self.data = data

    def create(self):
        if self.exists:
            raise ReleaseException(f"Milestone {self.version} already exists")

        milestone = gitlab.post(f"milestones",
            title=f"v{version}",
            description=f"Collection of issues intended to be resolved in release {version}",
            )
        logger.debug(f"Gitlab replied: {milestone}")
        self.parse_info(milestone)

    def template_data(self):
        return {
                "name": self.name,
                "url": self.url,
                "local_id": self.local_id,
                "gitlab_id": self.gitlab_id,
                }
