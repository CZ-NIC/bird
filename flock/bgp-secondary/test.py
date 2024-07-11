#!/usr/bin/python3

import asyncio
import ipaddress
import jinja2
import os
import pathlib
import sys

sys.path.insert(0, "/home/maria/flock")

from flock.Hypervisor import Hypervisor

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "lib"))

from BIRD.CLI import CLI, Transport

os.chdir(pathlib.Path(__file__).parent)

class MinimalistTransport(Transport):
    def __init__(self, socket, machine):
        self.sock = socket
        self.machine = machine

    async def send_cmd(self, *args):
        return await self.sock.send_cmd("run_in", self.machine, "./birdc", "-l", *args)

async def main():
    h = Hypervisor("bgp-secondary")
    await h.prepare()
    os.symlink(pathlib.Path("bgp-secondary.log").absolute(), h.basedir / "flock.log")
    await h.start()

    src, dest = await asyncio.gather(
            h.control_socket.send_cmd_early("machine", "src", { "type": "minimalist"}),
            h.control_socket.send_cmd_early("machine", "dest", { "type": "minimalist"}),
            )

    for q in src, dest:
        q["workdir"] = pathlib.Path(q["workdir"])

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
        for t in ("ipv4", "ipv6"):
            link[m][t] = ipaddress.ip_interface(link[m][t])

    print(link, src, dest)

    env = jinja2.Environment()
    src_conf = open("bird_src.conf", "r").read()
    jt = env.from_string(src_conf)
    with open(src["workdir"] / "bird.conf", "w") as f:
        f.write(jt.render( link=link ))

    dest_conf = open("bird_dest.conf", "r").read()
    jt = env.from_string(dest_conf)
    with open(dest["workdir"] / "bird.conf", "w") as f:
        f.write(jt.render( link=link ))

    with open(pathlib.Path.cwd() / ".." / ".." / "bird", "rb") as b:
        with open(dest["workdir"] / "bird", "wb") as d:
            d.write(dta := b.read())

        with open(src["workdir"] / "bird", "wb") as d:
            d.write(dta)

    with open(pathlib.Path.cwd() / ".." / ".." / "birdc", "rb") as b:
        with open(dest["workdir"] / "birdc", "wb") as d:
            d.write(dta := b.read())

        with open(src["workdir"] / "birdc", "wb") as d:
            d.write(dta)

    os.chmod(dest["workdir"] / "bird", 0o755)
    os.chmod(src["workdir"] / "bird", 0o755)
    os.chmod(dest["workdir"] / "birdc", 0o755)
    os.chmod(src["workdir"] / "birdc", 0o755)

    print(await asyncio.gather(*[
        h.control_socket.send_cmd("run_in", where, "./bird", "-l")
        for where in ("src", "dest")
        ]))

    await asyncio.sleep(5)

    src_cli = CLI(MinimalistTransport(h.control_socket, "src"))
    dest_cli = CLI(MinimalistTransport(h.control_socket, "dest"))

    print(await asyncio.gather(*[
        where.show_route()
        for where in (src_cli, dest_cli)
        ]))

    await asyncio.sleep(1)

    for p in ("p170", "p180", "p190", "p200"):
        await src_cli.enable(p)
        await asyncio.sleep(1)

        shr = await asyncio.gather(*[
            where.show_route()
            for where in (src_cli, dest_cli)
            ])

        print(shr[0]["out"].decode(), shr[1]["out"].decode())

        await asyncio.sleep(1)

    print(await asyncio.gather(*[
        where.show_route()
        for where in (src_cli, dest_cli)
        ]))

    print(await asyncio.gather(*[
        c.down()
        for c in (src_cli, dest_cli)
        ]))

    await asyncio.sleep(5)
    for q in (dest, src):
        for f in ("bird", "birdc", "bird.conf", "bird.log"):
            (q["workdir"] / f).unlink()

    await h.control_socket.send_cmd("stop", True)

assert(__name__ == "__main__")
asyncio.run(main())
