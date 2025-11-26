import jinja2
import logging

logger = logging.getLogger(__name__)

class Templater:
    """
    Simple Jinja templater. Single instance per template, cached locally.
    Usage: Templater(path: str).render(data: kwargs)
    """
    instances = {}
    def __new__(cls, tpath):
        if tpath not in cls.instances:
            cls.instances[tpath] = super(Templater, cls).__new__(cls)

        return cls.instances[tpath]

    def __init__(self, tpath):
        self.j2env = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
        try:
            self.te = self.j2env.get_template(tpath)
        except Exception:
            logger.exception(f"Failed to load Jinja template from {tpath}")
            exit(1)

    def render(self, **data):
        """
        Render given data by this template.
        """
        return self.te.render(**data)
