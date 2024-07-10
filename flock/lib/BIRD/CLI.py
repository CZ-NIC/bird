class Transport:
    pass

class CLI:
    def __init__(self, transport: Transport):
        self.transport = transport

    async def down(self):
        return await self.transport.send_cmd("down")
