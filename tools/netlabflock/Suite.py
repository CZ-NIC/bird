from . import NetlabFlock
from . import flock

import asyncio
import os
import pathlib
import re

class TaskTreeNode:
    def __init__(self, run, *deps):
        self.run = run
        self.deps = deps
        self.done = asyncio.get_event_loop().create_future()

    async def run(self, *args, **kwargs):
        await asyncio.gather(*self.deps)
        self.done.set_result(await self.run(*args, **kwargs))

class Suite:
    def __init__(self, name: str):
        self.name = name
        self.dir = NetlabFlock.netlabdir / name
        if not self.dir.exists():
            raise Exception(f"Suite dir {self.dir} not found")

        self.rundir = pathlib.Path(os.environ['XDG_RUNTIME_DIR']) / "netlabflock"

    def help(self, *args: str):
        print("Usage: python3 -m netlabflock (start|stop|save|check) suitename [targetdir]")

    async def start(self):
        # Load config
        commands = []
        mach_setup = {}

        with open(self.dir / "config") as cf:
            fixed = re.sub("\\\\\n", "", cf.read())

            self.machines = None

            netlab_init_seen = False

            for cmd in fixed.split("\n"):
                cmd = cmd.strip()
                if cmd == "":
                    continue

                if cmd.startswith("NETLAB_NODES="):
                    assert(not netlab_init_seen)
                    self.machines = re.sub('^[^"]*"(.*?)"[^"]*', '\\1', cmd).split()
                    for m in self.machines:
                        ms = TaskTreeNode(self.machine_setup)
                        mach_setup[m] = ms
                        commands.append(ms.run(m))
                    continue

                if cmd == "netlab_init":
                    assert(not netlab_init_seen)
                    netlab_init_seen = True
                    continue

                cmd, *args = cmd.split()
                if cmd == "if_dummy":
                    commands.append(TaskTreeNode(self.if_dummy, mach_setup[args[0]].done).run(*args))
                elif cmd == "if_veth":
                    commands.append(TaskTreeNode(self.if_veth, mach_setup[args[0]].done, mach_setup[args[2]].done).run(*args))
                elif cmd == "netlab_start":
                    pass
                else:
                    print(f"Unknown command {cmd}")

        assert(netlab_init_seen)

        # Prepare Flock simulation
        flock.create(self.targetdir)

        await asyncio.gather(*commands)


    async def stop(self):
        print("stop", self.targetdir)
        flock.delete(self.targetdir)

    async def save(self):
        ...

    async def check(self):
        ...

    async def exec(self, cmd: str, targetdir: str = None):
        if targetdir is None:
            if not self.rundir.exists():
                self.rundir.mkdir()

            self.targetdir = self.rundir / self.name
        else:
            self.targetdir = pathlib.Path(targetdir)

        await {
                "start": self.start,
                "stop": self.stop,
                "save": self.save,
                "check": self.check,
                }[cmd]()

    async def machine_setup(self, machine: str):
        # TODO: do this async
        print(f"Start {machine}")
        flock.start(self.targetdir, machine)
        sp = await asyncio.create_subprocess_exec(
                str(NetlabFlock.toolsdir / "flock" / "box" / "flock-shell"),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.targetdir / machine))

        out, err = await sp.communicate("""
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.tcp_l3mdev_accept=0
sysctl net.ipv6.conf.all.forwarding=1
sysctl net.mpls.platform_labels=16384
ip link set lo up
""".encode())

        return (out, err)

    async def if_dummy(self, machine: str, name: str, ip4pref: str, ip6pref: str):
        ...

    async def if_veth(self, m1: str, n1: str, m2: str, n2: str, ip4pref: str, ip6pref: str = None):
        ...
