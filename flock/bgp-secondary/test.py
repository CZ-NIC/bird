#!/usr/bin/python3

import asyncio
import ipaddress
import jinja2
import os
import pathlib
import sys

sys.path.insert(0, "/home/maria/flock")

import flock.Hypervisor as Hypervisor

async def main():
    h = Hypervisor.Hypervisor("bgp-secondary")
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


    """
    print(await asyncio.gather(
            h.control_socket.send_cmd("run_in", "src", "ip", "a"),
            h.control_socket.send_cmd("run_in", "dest", "ip", "a"),
            ))
            """
    await asyncio.sleep(30)

    print(await asyncio.gather(*[
        h.control_socket.send_cmd("run_in", where, "./birdc", "-l", "down")
        for where in ("src", "dest")
        ]))

    await asyncio.sleep(1)
    await h.control_socket.send_cmd("stop", True)

assert(__name__ == "__main__")
asyncio.run(main())
