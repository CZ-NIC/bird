import asyncio
from BIRD.Basic import Basic, Code

class StatusException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Failed to parse status: " + msg)

class Status(Basic):
    async def update(self):
        self.data = {}

        await self.bird.cli.open()
        data = await self.bird.cli.socket.command("show status")

        if data[0]["code"] != Code.Version:
            raise StatusException(f"BIRD version not on the first line, got {data[0]['code']}")
        
        self.data["version"] = data[0]["data"]

        if data[-1]["code"] != Code.Status:
            raise StatusException(f"BIRD status not on the last line, got {data[-1]['code']}")

        self.data["status"] = data[-1]["data"]

#        for d in data[1:-1]:



class VersionException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Failed to parse version from socket hello: " + msg)

class Version(Basic):
    async def update(self):
        await self.bird.cli.open()
        hello = self.bird.cli.hello

        if hello["code"] != Code.Welcome:
            raise VersionException(f"code is {hello['code']}, should be 1")

        s = hello["data"].split(" ")
        if len(s) != 3 or s[2] != "ready.":
            raise VersionException(f"malformed hello: {hello['data']}")

        self.data = {
                "name": s[0],
                "version": s[1],
                }
