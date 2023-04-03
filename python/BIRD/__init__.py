import asyncio
from pathlib import Path

from BIRD.Basic import BIRDException
from BIRD.Socket import Socket
from BIRD.Status import Status, Version

class CLI:
    def __init__(self, name):
        self.socket = Socket(name)
        self.connected = False
        self.hello = None

    async def open(self):
        if self.hello is not None:
            return

        h = await self.socket.open()
        if len(h) != 1:
            raise BIRDException("CLI hello should have 1 line, has {len(h)} lines: {h}")

        self.hello = h[0]

    async def close(self):
        if self.hello is None:
            return

        await self.socket.close()
        self.hello = None

class BIRD:
    def __init__(self, socket=Path("bird.ctl")):
        self.cli = CLI(socket)
        self.version = Version(self)
        self.status = Status(self)

        self.within = False

    async def __aenter__(self):
        if self.within:
            raise BIRDException("Tried to enter BIRD context (async with) more than once")

        self.within = True
        return self

    async def __aexit__(self, *args):
        await self.cli.close()
        self.within = False
