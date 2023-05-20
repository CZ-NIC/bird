import asyncio

class BIRDException(Exception):
    pass

class Basic:
    def __init__(self, bird):
        self.bird = bird
        self.data = None

    def __getattr__(self, name):
        if self.data is None:
            raise BIRDException(f"Call update() to get data")

        if name not in self.data:
            raise BIRDException(f"Unknown key {name} in {type(self)}")

        return self.data[name]

    def __repr__(self):
        return f"{type(self).__name__}({self.data})"

    async def load(self):
        if self.data is None:
            await self.update()

class Code:
    OK = 0
    Welcome = 1
    Status = 13
    Version = 1000
