import asyncio
import re

from python.asyncinotify.src.asyncinotify import Inotify, Mask

class UnexpectedLogException(Exception):
    pass

class LogSeen:
    lino: int
    buf: str
    groups: object

class LogExpectedStub:
    def __init__(self, pattern):
        self.pattern = re.compile(pattern) if type(pattern) is str else pattern
        self.seen = []

    def check(self, buf):
        return self.pattern.match(buf)

    def store(self, data):
        self.seen.append(data)

class LogExpectedFuture(LogExpectedStub):
    def __init__(self, pattern):
        super().__init__(pattern)
        self.done = asyncio.Future()

    def store(self, data):
        self.done.set_result(data)

class LogChecker:
    def __init__(self, name, expected=None):
        self.name = name
        self.expected = [
                LogExpectedStub(e) if isinstance(e, str) else e
                for e in expected
                ] if expected is not None else []
        self.task = None

    def check(self, buf):
        for p in self.expected:
            if (g := p.check(buf)) is not None:
                p.store(g)
                return

        raise UnexpectedLogException(buf)

    async def run(self):
        with (Inotify() as inot, open(self.name, "r") as f):
            inot.add_watch(self.name, Mask.MODIFY)
            buf = None
            while True:
                buf = f.readline()
                if len(buf) > 0 and buf[-1] == "\n":
                    self.check(buf)
                else:
                    break

            async for event in inot:
                while True:
                    buf += f.readline()
                    if len(buf) > 0 and buf[-1] == "\n":
                        self.check(buf)
                        buf = ""
                    else:
                        break

    def append(self, pat):
        if type(pat) is str:
            self.expected.append(LogExpectedStub(pat))
        else:
            self.expected.append(pat)
