import asyncio

from BIRD.Basic import Basic, BIRDException, Code

class ProtocolException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, f"Failed to parse protocol {self.protocol_name}: {msg}")

class ProtocolListException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, f"Failed to parse protocol list: {msg}")

class ProtocolList(Basic):
    match = {}
#    def __init__(self, **kwargs):
#        super().__init__(**kwargs)

    def register(sub):
        if sub.match in ProtocolList.match:
            raise BIRDException(f"Protocol match {sub.match} already registered for {ProtocolList.match[sub.match]}") 

        ProtocolList.match[sub.match] = sub

    async def update(self):
        self.data = {}

        await self.bird.cli.open()
        data = await self.bird.cli.socket.command("show protocols all")

        # Get header
        if data[0]["code"] != Code.ProtocolListHeader:
            raise ProtocolListException(f"First line is not protocol list header, got {data[0]}")

        if data[0]["data"].split() != ['Name', 'Proto', 'Table', 'State', 'Since', 'Info']:
            raise ProtocolListException(f"Strange protocol list header: {data[0]['data']}")

        data.pop(0)

        for line in data:
            if line["code"] == Code.ProtocolInfo:
                kwargs = Protocol.parse_info(line["data"])
                
                if (name := kwargs["name"]) in self.data:
                    raise ProtocolListException(f"Duplicate protocol {name}")

                if (m := kwargs["match"]) in self.match:
                    del kwargs["match"]
                    kwargs["bird"] = self.bird
                    self.data[name] = self.match[m](**kwargs)
                else:
                    raise ProtocolListException(f"Unknown protocol kind {m}")


class Protocol(Basic):
    def __init__(self, name, state, last_change, info, **kwargs):
        super().__init__(**kwargs)

        self.name = name
        self.state = state
        self.last_change = last_change
        self.info = info

    def parse_info(data):
        s = data.split(maxsplit=5) + [None]
        assert(len(s) <= 7)
        if len(s) < 6:
            raise ProtocolListException(f"Strange protocol info: {data}")

        s.append(None)
        s.pop(2) # drop the default table name, it's a BIRD 1 anachronism
        return dict(zip(
            ["name", "match", "state", "last_change", "info"],
            s
            ))

import BIRD.Protocol.Kernel
import BIRD.Protocol.Babel
import BIRD.Protocol.RAdv
