#!/usr/bin/python3

import asyncio
from python.BIRD.Test import Test, BIRDInstance, DumpRIB

class ThisTest(Test):
    async def prepare(self):
        # Set epoch
        self.epoch = 0

        # Prepare machines and links
        self.src, self.dest = await self.machines(
                "src", "dest",
                t=BIRDInstance,
                )
        self.links = {
                "L": await self.link("L", "src", "dest")
                }

    async def test(self):
        # Startup check
        await DumpRIB(self, 10, "startup")()

        wtb = ["p170", "p180", "p190", "p200"]
        btw = [*reversed(wtb)]

        # Enable worst to best
        for p in wtb:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Disable worst to best
        for p in wtb:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Enable best to worst
        for p in btw:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Disable best to worst
        for p in btw:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Re-enable all at once
        await asyncio.gather(*[ self.src.enable(p) for p in wtb ])
        await DumpRIB(self, 5, f"add-all")()

        # Update configuration
        self.epoch = 1
        self.src.write_config(test=self)
        await self.src.configure(expected_logs=[
            f"<INFO> Reconfiguring$",
            f"<INFO> Reloading channel LINK.ipv6",
            f"<INFO> Reconfigured$",
            ])
        await DumpRIB(self, 5, f"check-reconfig")()

        # Disable worst to best
        for p in wtb:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Enable best to worst
        for p in btw:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Disable best to worst
        for p in btw:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Enable worst to best
        for p in wtb:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Update configuration once again
        self.epoch = 2
        self.src.write_config(test=self)
        await self.src.configure(expected_logs=[
            f"<INFO> Reconfiguring$",
            f"<INFO> Reloading channel LINK.ipv6",
            f"<INFO> Reconfigured$",
            ])
        await DumpRIB(self, 5, f"check-reconfig")()

        # Disable best to worst
        for p in btw:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Enable best to worst
        for p in btw:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Disable worst to best
        for p in wtb:
            await self.src.disable(p)
            await DumpRIB(self, 1, f"disable-{p}")()

        # Enable worst to best
        for p in wtb:
            await self.src.enable(p)
            await DumpRIB(self, 1, f"enable-{p}")()

        # Pre-cleanup log checker
        self.src.default_log_checker.append(f"{self.src.logprefix} <RMT> LINK: Received: Administrative shutdown")
        self.dest.default_log_checker.append(f"{self.dest.logprefix} <RMT> LINK: Received: Administrative shutdown")

        # Regular cleanup
        await self.cleanup()