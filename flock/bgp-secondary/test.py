#!/usr/bin/python3

import asyncio
from python.BIRD.Test import Test, BIRDInstance

class ThisTest(Test):
    async def run(self):
        # Prepare machines and links
        self.src, self.dest = await self.machines(
                "src", "dest",
                t=BIRDInstance,
                )
        self.links = {
                "L": await self.link("L", "src", "dest")
                }

        # Start machines and links
        await self.start()

        # Partial test
        await self.route_dump(5)

        for p in ("p170", "p180", "p190", "p200"):
            await self.src.enable(p)
            await self.route_dump(1)

        await self.cleanup()
