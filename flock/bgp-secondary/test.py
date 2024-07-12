#!/usr/bin/python3

import asyncio
import ipaddress
import jinja2
import os
import pathlib
import sys

selfpath = pathlib.Path(__file__)
name = selfpath.parent.stem

sys.path.insert(0, str(selfpath.parent.parent / "lib"))

from BIRD.Test import Test, BIRDInstance

os.chdir(pathlib.Path(__file__).parent)

class ThisTest(Test):
    async def start(self):
        self.src, self.dest = await self.machines(
                "src", "dest",
                t=BIRDInstance,
                )
        self.links = {
                "L": await self.link("L", "src", "dest")
                }

async def main():
    t = ThisTest(name)
    await t.start()

    h = t.hypervisor

    print(t.links, t.src, t.dest)

    env = jinja2.Environment()
    src_conf = open("bird_src.conf", "r").read()
    jt = env.from_string(src_conf)
    with open(t.src.workdir / "bird.conf", "w") as f:
        f.write(jt.render( links=t.links ))

    dest_conf = open("bird_dest.conf", "r").read()
    jt = env.from_string(dest_conf)
    with open(t.dest.workdir / "bird.conf", "w") as f:
        f.write(jt.render( links=t.links ))

    print(await asyncio.gather(*[
        h.control_socket.send_cmd("run_in", where, "./bird", "-l")
        for where in ("src", "dest")
        ]))

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

    print(await asyncio.gather(*[
        c.down()
        for c in (t.src, t.dest)
        ]))

    await asyncio.sleep(5)
    await t.cleanup()
    for q in (t.dest, t.src):
        for f in ("bird.conf", "bird.log"):
            (q.workdir / f).unlink()

    await h.control_socket.send_cmd("stop", True)

assert(__name__ == "__main__")
asyncio.run(main())
