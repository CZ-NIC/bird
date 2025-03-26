import os
import pathlib
from . import flock

class NetlabFlock:
    toolsdir = pathlib.Path(__file__).parent.parent
    netlabdir = toolsdir / "bird-tools" / "netlab"

if not NetlabFlock.netlabdir.exists():
    raise Exception(f"Netlab dir not found at {NetlabFlock.netlabdir.absolute()}, did you run git submodule update --init?")

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
        print("start", self.targetdir)
        flock.create(self.targetdir)

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

