import contextlib
import io
import logging
import zipfile

from .Common import ReleaseException
from .Gitlab import gitlab

logger = logging.getLogger(__name__)

class Pipeline:
    def __init__(self, data=None, **kwargs):
        if data is None:
            data = gitlab.get(f"pipelines", **kwargs)
            if len(data) == 0:
                self.exists = False
            elif len(data) == 1:
                self.parse_info(data[0])
            else:
                raise ReleaseException(f"Too many pipelines for singleton query: {', '.join([ d['iid'] for d in data ])}")
        else:
            self.parse_info(data)

    @classmethod
    def load(cls, **kwargs):
        data = gitlab.get_all(f"pipelines", **kwargs)
        return [ cls(data=d) for d in data ]

    def parse_info(self, data):
        self.local_id = data['iid']
        self.gitlab_id = data['id']

    def __getattr__(self, key):
        if key == "jobs":
            self.jobs = { d['name']: Job(d) for d in gitlab.get_all(f"pipelines/{self.gitlab_id}/jobs") }
            return self.jobs
        else:
            raise AttributeError(f"No attribute {key} in Pipeline")

    def __repr__(self):
        return f"Pipeline(local={self.local_id}, gitlab={self.gitlab_id})"

    def __str__(self):
        return f"#P{self.local_id}/{self.gitlab_id}"

class Job:
    def __init__(self, data):
        if type(data) is int:
            data = gitlab.get(f"jobs/{data}")

        self.id = data['id']
        self.finished = data['finished_at']
        self.name = data['name']
        self.ref = data['ref']
        self.url = data['web_url']

    def info(self):
        return {
                "id": self.id,
                "finished": self.finished,
                "name": self.name,
                "ref": self.ref,
                "url": self.url,
                }

    @contextlib.contextmanager
    def artifacts_zipfile(self):
        with zipfile.ZipFile(io.BytesIO(gitlab.get(f"jobs/{self.id}/artifacts/", raw=True))) as z:
            yield z

    def __str__(self):
        return f"#J{self.id}"

    def __repr__(self):
        return f"Job(id={self.id}, name={self.name}), ref={self.ref}"
