#!/usr/bin/python3

import asyncio
from python.BIRD.Test import Test, BIRDInstance, DumpRIB, DumpLinuxKRT, DumpOSPFNeighbors
from python.BIRD.LogChecker import LogExpectedStub

class ThisTest(Test):
    async def prepare(self):
        # Set epoch

        # Prepare machines and links
        await self.machines(
                *[ f"m{n}" for n in range(1,9) ],
                t=BIRDInstance,
                )

        for m in self.machine_index.values():
            m.conf = "template.conf"
            m.default_log_checker.expected += [
                    LogExpectedStub(f"{m.logprefix} <INFO> Chosen router ID .*")
                    ]

        await asyncio.gather(*[
            self.link("ve31", "m3", "m1"),
            self.link("ve12", "m1", "m2"),
            self.link("ve23", "m2", "m3"),
            self.link("ve57", "m5", "m7"),
            self.link("ve78", "m7", "m8"),
            self.link("ve86", "m8", "m6"),
            self.link("multi", "m3", "m4", "m5", "m6"),
            ])

    async def test(self):
        # Startup check
        await asyncio.gather(*[
            DumpRIB(self, 30, "rib-startup")(),
            DumpLinuxKRT(self, 30, "fib-startup")(),
            DumpOSPFNeighbors(self, 30, "ospf-neighbors", protocols=["ospf4", "ospf6"])(),
            ])
