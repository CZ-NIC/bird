import logging
import requests

from .Git import git

logger = logging.getLogger(__name__)

class GitlabException(Exception):
    def __str__(self):
        return f"Gitlab request {self.args[0]} failed with {self.args[1].status_code}"

# A singleton class providing raw Gitlab API
class Gitlab:
    stem = "https://gitlab.nic.cz/api/v4/projects/labs%2Fbird/"

    @classmethod
    def get(cls, uri, **kwargs):
        response = requests.get(cls.stem + uri, params=kwargs, headers={"PRIVATE-TOKEN": git.token()})
        if not response.ok:
            raise GitlabException(cls.stem + uri, response)

        return response.json()

    @classmethod
    def post(cls, uri, **kwargs):
        response = requests.post(cls.stem + uri, headers={"PRIVATE-TOKEN": git.token()}, **kwargs)
        if not response.ok:
            raise GitlabException({ "uri": cls.stem + uri, **kwargs }, response)

        return response.json()

gitlab = Gitlab()
