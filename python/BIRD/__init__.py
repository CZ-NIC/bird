import asyncio
from pathlib import Path
from datetime import datetime

from BIRD.Basic import BIRDException
from BIRD.Socket import Socket
from BIRD.Status import Status, Version
from BIRD.Protocol import ProtocolList
from BIRD.Actions import Actions

from BIRD.Config import Timestamp, ProtocolConfig, DeviceProtocolConfig

class Config:
    def __init__(self, auto_device=True):
        self._items = []
        self.symbols = {}
        self.auto_device = auto_device

        self.add(Timestamp("Config object created"))

    class FinalizedConfig:
        def __init__(self, config):
            self.config = config
            self.auto_device = None

        def __enter__(self):
            if self.config.auto_device:
                self.auto_device = DeviceProtocolConfig(comment="Default device protocol; set Config(auto_device=False) to remove")

            self.begin = Timestamp("Config dump started")
            self.config.add(self.begin)

            return self

        def dump(self, _file):
            for i in self.config._items:
                if i is None:
                    continue
                if isinstance(i, DeviceProtocolConfig):
                    self.auto_device = None

                i.writelines(_file)

            if self.auto_device is not None:
                self.auto_device.writelines(_file)

            Timestamp("Config dump finished").writelines(_file)

        def __exit__(self, *args):
            self.config.remove(self.begin)

    def finalized(self):
        return self.FinalizedConfig(self)

    def write(self, _file):
        with self.finalized() as sf:
            with open(_file, "w") as f:
                sf.dump(f)

    def add(self, item):
        # Merge defined symbols
        for s in item.symbols:
            if s in self.symbols:
                # Found: rollback and fail
                for s in item.symbols:
                    if s in self.symbols:
                        del self.symbols[s]
                raise BIRDException("Can't add item to config: symbol {s} already exists")
            self.symbols[s] = item.symbols[s]

        # Store backref (weak)
        item.config[self] = len(self._items)

        # Fwdref
        self._items.append(item)

    def remove(self, item):
        # Check backref existence
        if self not in item.config:
            raise BIRDException("Can't remove item from config: isn't there")

        # Remove fwdref and cleanup Nones
        self._items[item.config[self]] = None
        while self._items[-1] is None:
            self._items.pop()

        # Remove backref
        del item.config[self]

class CLI:
    def __init__(self, name):
        self.socket = Socket(name)
        self.connected = False
        self.hello = None
        self.lock = asyncio.Lock()

    async def open(self):
        if self.hello is not None:
            return

        h = await self.socket.open()
        if len(h) != 1:
            raise BIRDException("CLI hello should have 1 line, has {len(h)} lines: {h}")

        self.hello = h[0]

    async def close(self):
        if self.hello is None:
            return

        await self.socket.close()
        self.hello = None

class BIRD:
    def __init__(self, socket=Path("bird.ctl")):
        self.cli = CLI(socket)
        self.version = Version(bird=self)
        self.status = Status(bird=self)
        self.protocols = ProtocolList(bird=self)
        self.actions = Actions(bird=self)

        self.within = False

    async def __aenter__(self):
        if self.within:
            raise BIRDException("Tried to enter BIRD context (async with) more than once")

        self.within = True
        await self.cli.lock.acquire()
        return self

    async def __aexit__(self, *args):
        await self.cli.close()
        self.cli.lock.release()
        self.within = False
