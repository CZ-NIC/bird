import asyncio
import ipaddress
import jinja2
import os
import pathlib
import sys
import yaml

sys.path.insert(0, "/home/maria/flock")

from flock.Hypervisor import Hypervisor
from flock.Machine import Machine
from .CLI import CLI, Transport

# TODO: move this to some aux file
class Differs(Exception):
    def __init__(self, a, b, tree):
        self.a = a
        self.b = b
        self.tree = tree

    @classmethod
    def false(cls, a, b, deep, tree):
        if deep:
            raise cls(a, b, tree)
        else:
            return False

def deep_eq(a, b, deep=False):
    if a == b:
        return True

    # Do not iterate over strings
    if type(a) is str and type(b) is str:
        return Differs.false(a, b, deep, tree=[])

    try:
        for k,v in a.items():
            try:
                deep_eq(v, b[k], True)
            except Differs as d:
                d.tree.append(k)
                raise d
            except KeyError:
                return Differs.false(v, None, deep, tree=[k])

        for k in b:
            if not k in a:
                return Differs.false(None, b[k], deep, tree=[k])

    except AttributeError:
        try:
            if len(a) != len(b):
                return Differs.false(len(a), len(b), deep, tree=[len])

            for i in range(len(a)):
                try:
                    deep_eq(a[i], b[i])
                except Differs as d:
                    d.tree.append(i)
                    raise d
        except TypeError:
            return Differs.false(a, b, deep, [])

    return True

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

    def cleanup(self, target):
        for bn in self.files:
            (target / bn).unlink()

default_bindir = BIRDBinDir.get(".")

class BIRDInstance(CLI):
    def __init__(self, mach: Machine, bindir=None, conf=None):
        self.mach = mach
        self.workdir = self.mach.workdir
        self.bindir = BIRDBinDir.get(bindir) if bindir is not None else default_bindir
        self.conf = conf if conf is not None else f"bird_{mach.name}.conf"

        super().__init__(
                transport=MinimalistTransport(
                    socket=mach.hypervisor.control_socket,
                    machine=self.mach.name
                    )
                )

    async def start(self, test):
        self.bindir.copy(self.workdir)

        with (open(self.conf, "r") as s, open(self.workdir / "bird.conf", "w") as f):
            f.write(jinja2.Environment().from_string(s.read()).render(t=test))

        await test.hcom("run_in", self.mach.name, "./bird", "-l")

    async def cleanup(self):
        # Send down command and wait for BIRD to actually finish
        await self.down()
        while (self.workdir / "bird.ctl").exists():
            await asyncio.sleep(0.1)

        # Remove known files
        for f in ("bird.conf", "bird.log"):
            (self.workdir / f).unlink()

        self.bindir.cleanup(self.workdir)

class Test:
    ipv6_prefix = ipaddress.ip_network("2001:db8::/32")
    ipv4_prefix = ipaddress.ip_network("192.0.2.0/24")

    ipv6_link_pxlen = 64
    ipv4_link_pxlen = 28

    SAVE = 1
    CHECK = 2

    show_difs = False

    # 198.51.100.0/24, 203.0.113.0/24

    def __init__(self, name, mode: int):
        self.name = name
        self.hypervisor = Hypervisor(name)
        self.machine_index = {}
        self.mode = mode
        self._started = None
        self._starting = False

        self.ipv6_pxgen = self.ipv6_prefix.subnets(new_prefix=self.ipv6_link_pxlen)
        self.ipv4_pxgen = self.ipv4_prefix.subnets(new_prefix=self.ipv4_link_pxlen)

        self.route_dump_id = 0

    async def hcom(self, *args):
        if self._started is None:
            self._started = asyncio.Future()

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
        for n in names:
            if n in self.machine_index:
                raise Exception(f"Machine {n} duplicate")

        info = await asyncio.gather(*[
            self.hcom("machine", name, { "type": "minimalist" })
            for name in names
            ])

        inst = [
                t(mach=Machine.new(
                    name=n,
                    hypervisor=self.hypervisor,
                    **i
                    ),
                  ) for n,i in zip(names, info)
                ]

        for n,i in zip(names, inst):
            self.machine_index[n] = i

        return inst

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

    async def start(self):
        await asyncio.gather(*[ v.start(test=self) for v in self.machine_index.values() ])

    async def cleanup(self):
        await asyncio.gather(*[ v.cleanup() for v in self.machine_index.values() ])
        await self.hcom("stop", True)

    async def route_dump(self, timeout, name, machines=None, check_timeout=10, check_retry_timeout=0.5):
        # Compile dump ID
        self.route_dump_id += 1
        if name is None:
            name = f"dump-{self.route_dump_id:04d}.yaml"
        else:
            name = f"dump-{self.route_dump_id:04d}-{name}.yaml"

        # Collect machines to dump
        if machines is None:
            machines = self.machine_index.values()
        else:
            machines = [
                    m if isinstance(m, CLI) else self.machine_index[m]
                    for m in machines
                    ]

        # Define the obtainer function
        async def obtain():
            dump = await asyncio.gather(*[
                where.show_route()
                for where in machines
                ])
            for d in dump:
                for t in d["tables"].values():
                    for n in t["networks"].values():
                        for r in n["routes"]:
                            assert("when" in r)
                            r["when"] = True
            return dump

        match self.mode:
            case Test.SAVE:
                await asyncio.sleep(timeout)
                dump = await obtain()
                with open(name, "w") as y:
                    yaml.dump_all(dump, y)
                print(f"{name}\t{self.route_dump_id}\t[ SAVED ]")

            case Test.CHECK:
                with open(name, "r") as y:
                    c = [*yaml.safe_load_all(y)]

                seen = []
                try:
                    async with asyncio.timeout(check_timeout) as to:
                        while True:
                            dump = await obtain()
                            try:
                                deep_eq(c, dump, True)
#                            if deep_eq(c, dump):
                                spent = asyncio.get_running_loop().time() - to.when() + check_timeout
                                print(f"{name}\t{self.route_dump_id}\t[  OOK  ]\t{spent:.6f}s")
                                return True
                            except Differs as d:
                                if self.show_difs:
                                    print(f"Differs at {' -> '.join([str(s) for s in reversed(d.tree)])}: {d.a} != {d.b}")

                            seen.append(dump)
                            await asyncio.sleep(check_retry_timeout)
                except TimeoutError as e:
                    print(f"{name}\t{self.route_dump_id}\t[ BAD  ]")
                    for q in range(len(seen)):
                        with open(f"__result_bad_{q}__{name}", "w") as y:
                            yaml.dump_all(seen[q], y)

                    return False

            case _:
                raise Exception("Invalid test mode")

if __name__ == "__main__":
    name = sys.argv[1]
    mode = Test.CHECK

    if name == "-s":
        name = sys.argv[2]
        mode = Test.SAVE

    p = (pathlib.Path(__file__).parent.parent.parent / "flock" / name).absolute()
    sys.path.insert(0, str(p))

#    if "MAKEFLAGS" in os.environ:
#        print(os.environ["MAKEFLAGS"])

    import test

    os.chdir(p)
    asyncio.run(test.ThisTest(name, mode).run())
