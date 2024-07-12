#!/usr/bin/python3

import asyncio
from python.BIRD.Test import Test, BIRDInstance

class ThisTest(Test):
    async def start(self):
        self.src, self.dest = await self.machines(
                "src", "dest",
                t=BIRDInstance,
                )
        self.links = {
                "L": await self.link("L", "src", "dest")
                }

        await super().start()

    async def run(t):
        await t.start()

        h = t.hypervisor

        print(t.links, t.src, t.dest)

        await asyncio.sleep(5)

        print(await asyncio.gather(*[
            where.show_route()
            for where in (t.src, t.dest)
            ]))

        await asyncio.sleep(1)

        for p in ("p170", "p180", "p190", "p200"):
            await t.src.enable(p)
            await asyncio.sleep(1)

            shr = await asyncio.gather(*[
                where.show_route()
                for where in (t.src, t.dest)
                ])

            print(shr[0]["out"].decode(), shr[1]["out"].decode())

            await asyncio.sleep(1)

        print(await asyncio.gather(*[
            where.show_route()
            for where in (t.src, t.dest)
            ]))

        await t.cleanup()
        await h.control_socket.send_cmd("stop", True)
