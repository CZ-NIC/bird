import logging
import requests
import time

from .Git import git

logger = logging.getLogger(__name__)

class GitlabException(Exception):
    def __str__(self):
        return f"Gitlab request {self.args[0]} failed with {self.args[1].status_code}"

# A singleton class providing raw Gitlab API
class Gitlab:
    stem = "https://gitlab.nic.cz/api/v4/projects/labs%2Fbird/"

    @classmethod
    def get(cls, uri, next_429_timeout=5, raw=False, **kwargs):
        response = requests.get(cls.stem + uri, params=kwargs, headers={"PRIVATE-TOKEN": git.token()})

        if response.status_code == 429:
            logger.info(f"Too many requests at {cls.stem + uri}, waiting {next_429_timeout} sec")
            time.sleep(next_429_timeout)
            return cls.get(uri, next_429_timeout=next_429_timeout*1.6, **kwargs)

        if not response.ok:
            raise GitlabException(cls.stem + uri, response)

        return response.content if raw else response.json()

    @classmethod
    def get_all(cls, uri, **kwargs):
        if "page" in kwargs:
            raise GitlabException(f"Don't touch page (set to {kwargs['page']}) in Gitlab.get_all()!")

        if "per_page" not in kwargs:
            kwargs['per_page'] = 100

        i = 1
        last = -1
        out = []
        while last < len(out):
            last = len(out)
            out += cls.get(uri, **kwargs, page=i)
            i += 1

        return out

    @classmethod
    def post(cls, uri, dry_run = False, **kwargs):
        if dry_run:
            logger.info(f"Would POST to {cls.stem + uri} JSON {kwargs}")
            return {}

        response = requests.post(cls.stem + uri, json=kwargs, headers={"PRIVATE-TOKEN": git.token()})
        if not response.ok:
            raise GitlabException({ "uri": cls.stem + uri, **kwargs }, response)

        return response.json()

gitlab = Gitlab()
