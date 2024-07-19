from . import ShowRoute

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

    async def show_route(self, table=["all"], args=[]):
        cmd = [ "show", "route" ]
        for t in table:
            cmd.append("table")
            cmd.append(t)

        cmd += args

        result = await self.transport.send_cmd(*cmd)
        if len(result["err"]):
            raise Exception(f"Command {cmd} returned {result['err'].decode()}, stdout={result['out'].decode()}")

        return ShowRoute.parse(result["out"].decode())
