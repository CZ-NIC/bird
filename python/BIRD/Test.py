import asyncio
import ipaddress
import jinja2
import json
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
from .Aux import dict_gather, dict_expand, deep_sort_lists, deep_eq, Differs

class MinimalistTransport(Transport):
    def __init__(self, hypervisor, machine):
        self.hypervisor = hypervisor
        self.machine = machine

    async def send_cmd(self, *args):
        return await self.hypervisor.run_in(self.machine, "./birdc", "-l", *args)

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
                    hypervisor=mach.hypervisor,
                    machine=self.mach.name,
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

        await test.hypervisor.run_in(self.mach.name, "./bird", "-l")

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
        self.test = test
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
        padlen = 48 - len(self.stem)
        if padlen < 6:
            padlen = 6
        label = self.stem + " "*padlen

        print(label)
        self.label_col = len(label)
        self.label_row = len(self.test.checks_running)
        self.test.checks_running.append(self)

        return self.run()

    def print_result(self, text):
        rows_up = len(self.test.checks_running) - self.label_row
        total_chars = len(text) + self.label_col
        print(f"\033[{rows_up}A\033[{self.label_col}C{text}\033[{total_chars}D\033[{rows_up}B", flush=True, end="")

    async def save(self):
        await asyncio.sleep(self.timeout)
        dump = await self.obtain()
        with open(self.file, "w") as y:
            yaml.dump(dump, y)
        self.print_result(f"[ SAVED ]")

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
                        self.print_result(f"[  OK  ]      {spent:.6f}s")
                        return True
                    except Differs as d:
                        if self.show_difs:
                            print(f"Differs at {' -> '.join([str(s) for s in reversed(d.tree)])}: {d.a} != {d.b}")

                    seen.append(dump)
                    await asyncio.sleep(self.check_retry_timeout)

        except TimeoutError as e:
            self.print_result(f"[ BAD  ]")
            for q in range(len(seen)):
                with open(f"__result_bad_{q}__{self.stem}", "w") as y:
                    yaml.dump(seen[q], y)

            return False

class DumpOnMachines(DumpCheck):
    def __init__(self, *args, machines=None, **kwargs):
        super().__init__(*args, **kwargs)

        # Collect machines to dump
        if machines is None:
            self.machines = self.test.machine_index.values()
        else:
            self.machines = [
                    m if isinstance(m, CLI) else self.test.machine_index[m]
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

class DumpLinuxKRT(DumpOnMachines):
    def __init__(self, *args, cmdargs=None, **kwargs):
        super().__init__(*args, **kwargs)
        if cmdargs is None:
            self.cmdargs = []
        else:
            self.cmdargs = cmdargs

    async def obtain_on_machine(self, mach):
        raw = await dict_gather({
                fam:
                self.test.hypervisor.run_in(mach.mach.name, "ip", "-j", f"-{fam}", "route", "show", *self.cmdargs)
                for fam in ("4", "6", "M")
                })

        for k,v in raw.items():
            if v["ret"] != 0 or len(v["err"]) != 0:
                raise Exception(f"Failed to gather krt dump for {k}: ret={v['ret']}, {v['err']}")

        return { k: deep_sort_lists(json.loads(v["out"])) for k,v in raw.items() }

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

        self.checks_running = []

        self.ipv6_pxgen = self.ipv6_prefix.subnets(new_prefix=self.ipv6_link_pxlen)
        self.ipv4_pxgen = self.ipv4_prefix.subnets(new_prefix=self.ipv4_link_pxlen)

    async def assure_running(self):
        if self._stopped is not None:
            return

        if self._started is None:
            self._started = asyncio.Future()

        if self._started.done():
            return

        if self._starting:
            await self._started
            return

        self._starting = True
        await self.hypervisor.prepare()
        os.symlink(pathlib.Path(f"{self.name}.log").absolute(), self.hypervisor.basedir / "flock.log")
        await self.hypervisor.start()

        self._started.set_result(await self.hypervisor.status(__rpc_timeout=5))

    async def machines(self, *names, t: type):
        for n in names:
            if n in self.machine_index:
                raise Exception(f"Machine {n} duplicate")

        await self.assure_running()

        info = await asyncio.gather(*[
            self.hypervisor.machine( name, { "type": "minimalist" })
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
        await self.assure_running()

        match len(machines):
            case 0:
                raise Exception("Link with no machines? HOW?!")
            case 1:
                raise NotImplementedError("dummy link")
            case _:
                linfo = await self.hypervisor.link(name, {
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
        await self.hypervisor.stop()
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


    async def krt_dump(self, timeout, name, *args, full=True, machines=None, check_timeout=10, check_retry_timeout=0.5):
        # Collect machines to dump
        if machines is None:
            machines = self.machine_index.values()
        else:
            machines = [
                    m if isinstance(m, CLI) else self.machine_index[m]
                    for m in machines
                    ]

        raw = await dict_gather({
                (mach.mach.name, fam):
                mach.mach.hypervisor.run_in(mach.mach.name, "ip", "-j", f"-{fam}", "route", "show", *args)
                for mach in machines
                for fam in ("4", "6", "M")
                })

        for k,v in raw.items():
            if v["ret"] != 0 or len(v["err"]) != 0:
                raise Exception(f"Failed to gather krt dump for {k}: ret={v['ret']}, {v['err']}")

        dump = dict_expand({ k: json.loads(v["out"]) for k,v in raw.items()})
        print(dump)

        name = "krt.yaml"
        with open(name, "w") as y:
            yaml.dump(dump, y)


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
