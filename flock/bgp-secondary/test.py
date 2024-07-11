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

async def main():
    t = ThisTest(name)
    await t.start()

    h = t.hypervisor

    link, = await asyncio.gather(
            h.control_socket.send_cmd("link", "L", {
                "machines": {
                    "src": { "name": "L" },
                    "dest": { "name": "L" },
                    },
                "ipv6": "2001:db8:0:1::/64",
                "ipv4": "10.0.1.0/29",
                }),
            )

    for m in link:
        for i in ("ipv4", "ipv6"):
            link[m][i] = ipaddress.ip_interface(link[m][i])

    print(link, t.src, t.dest)

    env = jinja2.Environment()
    src_conf = open("bird_src.conf", "r").read()
    jt = env.from_string(src_conf)
    with open(t.src.workdir / "bird.conf", "w") as f:
        f.write(jt.render( link=link ))

    dest_conf = open("bird_dest.conf", "r").read()
    jt = env.from_string(dest_conf)
    with open(t.dest.workdir / "bird.conf", "w") as f:
        f.write(jt.render( link=link ))

    with open(pathlib.Path.cwd() / ".." / ".." / "bird", "rb") as b:
        with open(t.dest.workdir / "bird", "wb") as d:
            d.write(dta := b.read())

        with open(t.src.workdir / "bird", "wb") as d:
            d.write(dta)

    with open(pathlib.Path.cwd() / ".." / ".." / "birdc", "rb") as b:
        with open(t.dest.workdir / "birdc", "wb") as d:
            d.write(dta := b.read())

        with open(t.src.workdir / "birdc", "wb") as d:
            d.write(dta)

    os.chmod(t.dest.workdir / "bird", 0o755)
    os.chmod(t.src.workdir / "bird", 0o755)
    os.chmod(t.dest.workdir / "birdc", 0o755)
    os.chmod(t.src.workdir / "birdc", 0o755)

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
    for q in (t.dest, t.src):
        for f in ("bird", "birdc", "bird.conf", "bird.log"):
            (q.workdir / f).unlink()

    await h.control_socket.send_cmd("stop", True)

assert(__name__ == "__main__")
asyncio.run(main())
