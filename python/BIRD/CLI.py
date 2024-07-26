from .ShowRoute import ShowRouteParser
from .ShowOSPF import ShowOSPFNeighborsParser

class Transport:
    pass

class CLI:
    def __init__(self, transport: Transport):
        self.transport = transport

    async def down(self):
        return await self.transport.send_cmd("down")

    async def configure(self, file=None, undo=False):
        if undo:
            return await self.transport.send_cmd("configure", "undo")
        if file:
            return await self.transport.send_cmd("configure", f'"{file}"')

        return await self.transport.send_cmd("configure")

    async def enable(self, proto: str):
        return await self.transport.send_cmd("enable", proto)

    async def disable(self, proto: str):
        return await self.transport.send_cmd("disable", proto)

    async def cmd_send_parse(self, parser, *cmd):
        result = await self.transport.send_cmd(*cmd)
        if len(result["err"]):
            raise Exception(f"Command {cmd} returned {result['err'].decode()}, stdout={result['out'].decode()}")

        for line in result["out"].decode().split("\n"):
            parser = parser.parse(line)

        return parser.parse(None).result

    async def show_route(self, table=["all"], args=[]):
        cmd = [ "show", "route" ]
        for t in table:
            cmd.append("table")
            cmd.append(t)

        cmd += args
        return await self.cmd_send_parse(ShowRouteParser(), *cmd)

    async def show_ospf_neighbors(self, proto: str):
        return await self.cmd_send_parse(ShowOSPFNeighborsParser(),
                                         "show", "ospf", "neighbors", proto)
