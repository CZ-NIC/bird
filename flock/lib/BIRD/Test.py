import asyncio
import ipaddress
import os
import pathlib
import sys

sys.path.insert(0, "/home/maria/flock")

from flock.Hypervisor import Hypervisor
from flock.Machine import Machine
from .CLI import CLI, Transport

class MinimalistTransport(Transport):
    def __init__(self, socket, machine):
        self.sock = socket
        self.machine = machine

    async def send_cmd(self, *args):
        return await self.sock.send_cmd("run_in", self.machine, "./birdc", "-l", *args)

class BIRDBinDir:
    index = {}

    def __init__(self, path):
        self.path = path

        f = [ "bird", "birdc", "birdcl", ]

        self.files = { k: None for k in f }
        self.mod = { k: None for k in f }
        self.loaded = False

    @classmethod
    def get(cls, where):
        w = pathlib.Path(where).absolute()
        try:
            return cls.index[s := str(w)]
        except KeyError:
            cls.index[s] = (b := cls(w))
            return b

    def load(self):
        for bn,v in self.files.items():
            if v is None:
                with open(self.path / bn, "rb") as b:
                    self.files[bn] = b.read()
                self.mod[bn] = (self.path / bn).stat().st_mode

        self.loaded = True

    def copy(self, target):
        if not self.loaded:
            self.load()

        for bn,v in self.files.items():
            if v is not None:
                with open(target / bn, "wb") as b:
                    b.write(v)
                (target / bn).chmod(self.mod[bn])

default_bindir = BIRDBinDir.get("..")

class BIRDInstance(CLI):
    def __init__(self, mach: Machine, bindir=None):
        self.mach = mach
        self.workdir = self.mach.workdir
        self.bindir = BIRDBinDir.get(bindir) if bindir is not None else default_bindir

        super().__init__(
                transport=MinimalistTransport(
                    socket=mach.hypervisor.control_socket,
                    machine=self.mach.name
                    )
                )

        self.bindir.copy(self.workdir)

class Test:
    ipv6_prefix = ipaddress.ip_network("2001:db8::/32")
    ipv4_prefix = ipaddress.ip_network("192.0.2.0/24")

    ipv6_link_pxlen = 64
    ipv4_link_pxlen = 28

    # 198.51.100.0/24, 203.0.113.0/24

    def __init__(self, name):
        self.name = name
        self.hypervisor = Hypervisor(name)
        self._started = asyncio.Future()
        self._starting = False

        self.ipv6_pxgen = self.ipv6_prefix.subnets(new_prefix=self.ipv6_link_pxlen)
        self.ipv4_pxgen = self.ipv4_prefix.subnets(new_prefix=self.ipv4_link_pxlen)

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

    async def machines(self, *names, t: type):
        info = await asyncio.gather(*[
            self.hcom("machine", name, { "type": "minimalist" })
            for name in names
            ])

        return [
                t(mach=Machine.new(
                    name=n,
                    hypervisor=self.hypervisor,
                    **i
                    )) for n,i in zip(names, info)
                ]

    async def link(self, name, *machines):
        match len(machines):
            case 0:
                raise Exception("Link with no machines? HOW?!")
            case 1:
                raise NotImplementedError("dummy link")
            case 2:
                linfo = await self.hcom("link", name, {
                    "machines": { m: { "name": name } for m in machines },
                    "ipv6": str(next(self.ipv6_pxgen)),
                    "ipv4": str(next(self.ipv4_pxgen)),
                    })
                for m in machines:
                    for i in ("ipv4", "ipv6"):
                        linfo[m][i] = ipaddress.ip_interface(linfo[m][i])

                return linfo

            case _:
                raise NotImplementedError("virtual bridge")
