import logging

from .Common import ReleaseException
from .Gitlab import gitlab

logger = logging.getLogger(__name__)

class Issue:
    def __init__(self, data=None, **kwargs):
        if data is None:
            data = gitlab.get(f"issues", **kwargs)
            if len(data) == 0:
                self.exists = False
            elif len(data) == 1:
                self.parse_info(data[0])
            else:
                raise ReleaseException(f"Too many issues for singleton query: {', '.join([ d['web_url'] for d in data ])}")
        else:
            self.parse_info(data)

    @classmethod
    def load(cls, **kwargs):
        data = gitlab.get(f"issues", **kwargs)
        return [ cls(data=d) for d in data ]

    def parse_info(self, data):
        self.local_id = data['iid']
        self.gitlab_id = data['id']
        self.url = data['web_url']
        self.name = data['title']
        self.labels = data['labels']
        self.milestone = data['milestone']
        self.text = data['description']
        self.exists = True
    
    @classmethod
    def create(cls, args):
        data = gitlab.post(f"issues", json={
#        print("Would post:", {
            "title": args.name,
            "labels": args.labels,
            "milestone_id": args.milestone.gitlab_id,
            "description": args.text,
            })
        return cls(data)

class ReleaseChecklistIssue(Issue):
    def __init__(self, release=None, data=None):
        if data is not None:
            self.parse_info(data)

        elif release is not None:
            super().__init__(
                    labels="release-checklist",
                    state="opened",
                    milestone=f"v{release.version}"
                    )
    
        else:
            raise ReleaseException("Nothing passed to ReleaseChecklistIssue() constructor")

    @classmethod
    def create(cls, release):
        super(ReleaseChecklistIssue, cls).create(
                name=f"BIRD {release.version} release ({ release.kind })",
                labels=f"release-{release.kind},release-checklist",
                milestone=release.milestone,
                text=Templater("tools/release-issue.md.j2").render(
                    **(self.issue_template_data()),
                    kind=self.kind,
                    )
                )
