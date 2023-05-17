from datetime import datetime
from weakref import WeakKeyDictionary

class ConfigObject:
    def __init__(self):
        self.symbols = {}
        self.config = WeakKeyDictionary()
        self.comment = None

    def __str__(self):
        return "" if self.comment is None else f"# {self.comment}\n"

class Timestamp(ConfigObject):
    def __init__(self, comment):
        super().__init__()
        self.comment = f"{comment} at {datetime.now()}"

class ProtocolConfig(ConfigObject):
    def __init__(self, name=None, template=None):
        super().__init__()
        self.name = name
        if template is not None:
            raise NotImplementedError()

    def block_inside(self, indent):
        return None

    def __str__(self):
        inside = self.block_inside(1)
        header = f"protocol {self.protocol_type}{'' if self.name is None else ' ' + self.name }"

        if inside is None:
            return header + " {}\n"
        else:
            return header + " {\n" + inside + "}\n"

class DeviceProtocolConfig(ProtocolConfig):
    name_prefix = "device"
    protocol_type = "device"

