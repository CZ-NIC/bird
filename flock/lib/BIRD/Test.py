import asyncio
import os
import pathlib
import sys

sys.path.insert(0, "/home/maria/flock")

from flock.Hypervisor import Hypervisor
from flock.Machine import Machine

class Test:
    machines_start = {}

    def __init__(self, name):
        self.name = name
        self.hypervisor = Hypervisor(name)
        self._started = asyncio.Future()
        self._starting = False

    async def hcom(self, *args):
        if self._started.done():
            return await self.hypervisor.control_socket.send_cmd(*args)

        if self._starting:
            await self._started
        else:
            self._starting = True
            await self.hypervisor.prepare()
            os.symlink(pathlib.Path("bgp-secondary.log").absolute(), self.hypervisor.basedir / "flock.log")
            await self.hypervisor.start()

            self._started.set_result(True)
            self._starting = False

        return await self.hypervisor.control_socket.send_cmd_early(*args)

    async def machines(self, *names):
        info = await asyncio.gather(*[
            self.hcom("machine", name, { "type": "minimalist" })
            for name in names
            ])

        return [
                Machine.new(
                    name=n,
                    hypervisor=self.hypervisor,
                    **i
                    ) for n,i in zip(names, info)
                ]

