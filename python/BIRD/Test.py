import asyncio
import ipaddress
import jinja2
import os
import pathlib
import sys
import yaml

flock_path = pathlib.Path(__file__).parent.parent / "flock"
if not (flock_path / "README.md").exists():
    print("Flock not found, have you run \"git submodule update\"?")
    exit(1)

sys.path.insert(0, str(flock_path))

from flock.Hypervisor import Hypervisor
from flock.Machine import Machine
from .CLI import CLI, Transport
from .LogChecker import LogChecker, LogExpectedFuture

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
    logprefix = "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[\d{4}\]"

    def __init__(self, mach: Machine, bindir=None, conf=None, logs=None):
        self.mach = mach
        self.workdir = self.mach.workdir
        self.bindir = BIRDBinDir.get(bindir) if bindir is not None else default_bindir
        self.conf = conf if conf is not None else f"bird_{mach.name}.conf"
        if logs is None:
            self.default_log_checker = LogChecker(name=self.workdir/"bird.log")
            self.logs = [ self.default_log_checker ]
        else:
            self.logs = logs

        super().__init__(
                transport=MinimalistTransport(
                    socket=mach.hypervisor.control_socket,
                    machine=self.mach.name
                    )
                )

    def write_config(self, test):
        with (open(self.conf, "r") as s, open(self.workdir / "bird.conf", "w") as f):
            f.write(jinja2.Environment().from_string(s.read()).render(t=test, m=self))

    async def logchecked(self, coro, pattern):
        if type(pattern) is str:
            exp = [ LogExpectedFuture(f"{self.logprefix} {pattern}") ]
        else:
            exp = [ LogExpectedFuture(f"{self.logprefix} {p}") for p in pattern ]

        self.default_log_checker.expected += exp

        main_task = asyncio.create_task(coro)

        try:
            async with asyncio.timeout(5):
                await asyncio.gather(
                        main_task,
                        *[ e.done for e in exp ]
                        )
        except TimeoutError as e:
            for e in exp:
                if not e.done.done():
                    print(f"Not done: {e}: {e.pattern}")

        for e in exp:
            self.default_log_checker.expected.remove(e)

    async def down(self):
        await self.logchecked(
                super().down(),
                [
                "<INFO> Shutting down",
                "<FATAL> Shutdown completed",
                ]
                )

    async def configure(self, *args, expected_logs=f"<INFO> Reconfiguring$", **kwargs):
        await self.logchecked(super().configure(*args, **kwargs), expected_logs)

    async def enable(self, proto: str):
        await self.logchecked(super().enable(proto), f"<INFO> Enabling protocol {proto}$")

    async def disable(self, proto: str):
        await self.logchecked(super().disable(proto), f"<INFO> Disabling protocol {proto}$")

    async def start(self, test):
        self.bindir.copy(self.workdir)
        self.write_config(test)

        await test.hcom("run_in", self.mach.name, "./bird", "-l")

        exp = LogExpectedFuture(f"{self.logprefix} <INFO> Started$")
        self.default_log_checker.expected.append(exp)

        async def started():
            async with asyncio.timeout(1):
                await exp.done

            self.default_log_checker.expected.remove(exp)

        return [
                l.run() for l in self.logs
                ] + [ started() ]

    async def cleanup(self):
        # Send down command and wait for BIRD to actually finish
        await self.down()
        while (self.workdir / "bird.ctl").exists():
            await asyncio.sleep(0.1)

        # Remove known files
        for f in (self.workdir / "bird.conf", *[ l.name for l in self.logs ]):
            f.unlink()

        self.bindir.cleanup(self.workdir)

class DumpCheck:
    def __init__(self, test, timeout, name, check_timeout=None, check_id=None, check_retry_timeout=0.5):
        self.timeout = timeout
        self.check_timeout = timeout if check_timeout is None else check_timeout
        self.check_retry_timeout = check_retry_timeout
        self.name = name
        self.show_difs = test.show_difs

        # Compile dump ID
        if check_id is None:
            try:
                test.check_id += 1
            except AttributeError:
                test.check_id = 1

            self.id = test.check_id
        else:
            self.id = check_id

        if name is None:
            self.stem = f"{self.id:04d}"
        else:
            self.stem = f"{self.id:04d}-{name}"

        self.file = f"dump-{self.stem}.yaml"

        match test.mode:
            case Test.SAVE:
                self.run = self.save
            case Test.CHECK:
                self.run = self.check
            case _:
                raise Exception("Invalid test mode")

    def __call__(self):
        print(f"{self.stem}\t", end="", flush=True)
        return self.run()

    async def save(self):
        await asyncio.sleep(self.timeout)
        dump = await self.obtain()
        with open(self.file, "w") as y:
            yaml.dump(dump, y)
        print(f"[ SAVED ]")

    async def check(self):
        with open(self.file, "r") as y:
            c = yaml.safe_load(y)

        seen = []
        try:
            async with asyncio.timeout(self.check_timeout) as to:
                while True:
                    dump = await self.obtain()
                    try:
                        deep_eq(c, dump, True)
#                            if deep_eq(c, dump):
                        spent = asyncio.get_running_loop().time() - to.when() + self.check_timeout
                        print(f"[  OOK  ]\t{spent:.6f}s")
                        return True
                    except Differs as d:
                        if self.show_difs:
                            print(f"Differs at {' -> '.join([str(s) for s in reversed(d.tree)])}: {d.a} != {d.b}")

                    seen.append(dump)
                    await asyncio.sleep(self.check_retry_timeout)

        except TimeoutError as e:
            print(f"[ BAD  ]")
            for q in range(len(seen)):
                with open(f"__result_bad_{q}__{self.stem}", "w") as y:
                    yaml.dump(seen[q], y)

            return False

class DumpOnMachines(DumpCheck):
    def __init__(self, test, *args, machines=None, **kwargs):
        super().__init__(test, *args, **kwargs)

        # Collect machines to dump
        if machines is None:
            self.machines = test.machine_index.values()
        else:
            self.machines = [
                    m if isinstance(m, CLI) else test.machine_index[m]
                    for m in machines
                    ]

    async def obtain(self):
        return await dict_gather({
            m.mach.name: self.obtain_on_machine(m)
            for m in self.machines
            })

class DumpRIB(DumpOnMachines):
    def __init__(self, *args, full=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = []
        if full:
            self.args.append("all")

    async def obtain_on_machine(self, mach):
        d = await mach.show_route(args=self.args)

        assert("version" in d)
        del d["version"]

        for t in d["tables"].values():
            for n in t["networks"].values():
                for r in n["routes"]:
                    for k in ("when", "!_l", "!_g", "!_s", "!_id"):
                        assert(k in r)
                        del r[k]
        return d



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
        self.link_index = {}
        self.mode = mode
        self._started = None
        self._starting = False
        self._stopped = None

        self.background_tasks = []

        self.ipv6_pxgen = self.ipv6_prefix.subnets(new_prefix=self.ipv6_link_pxlen)
        self.ipv4_pxgen = self.ipv4_prefix.subnets(new_prefix=self.ipv4_link_pxlen)

        self.route_dump_id = 0

    async def hcom(self, *args):
        if self._stopped is not None:
            return

        if self._started is None:
            self._started = asyncio.Future()

        if self._started.done():
            return await self.hypervisor.control_socket.send_cmd(*args)

        if self._starting:
            await self._started
        else:
            self._starting = True
            await self.hypervisor.prepare()
            os.symlink(pathlib.Path(f"{self.name}.log").absolute(), self.hypervisor.basedir / "flock.log")
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
            case _:
                linfo = await self.hcom("link", name, {
                    "machines": { m: { "name": name } for m in machines },
                    "ipv6": str(next(self.ipv6_pxgen)),
                    "ipv4": str(next(self.ipv4_pxgen)),
                    })
                for m in machines:
                    for i in ("ipv4", "ipv6"):
                        linfo[m][i] = ipaddress.ip_interface(linfo[m][i])

                self.link_index[name] = linfo
                return linfo

    async def start(self):
        return await asyncio.gather(*[ v.start(test=self) for v in self.machine_index.values() ])

    async def cleanup(self):
        await asyncio.gather(*[ v.cleanup() for v in self.machine_index.values() ])
        self.machine_index = {}
        await self.hcom("stop", True)
        self._stopped = True

    async def run(self):
        try:
            await self.prepare()
            tasks = [ t for q in await self.start() for t in q ]

            async def arun():
                await asyncio.gather(*tasks)
                raise Exception("No auxiliary task, what?")

            atask = asyncio.create_task(arun())

            async def trun():
                await self.test()
                atask.cancel()

            await asyncio.gather(atask, trun())

        except asyncio.exceptions.CancelledError as e:
            if not atask.cancelled():
                raise e
        finally:
            print("cleaning up")
            await self.cleanup()


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
