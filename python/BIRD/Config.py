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

class BlockOption:
    def __init__(self, config_text, _type, value):
        if not isinstance(value, _type):
            raise Exception("BlockOption value doesn't match declared type")

        self.config_text = config_text
        self._type = _type
        self.value = value

    def set(self, value):
        if value == self.value:
            return self
        else:
            return type(self)(self.config_text, self._type, value)

class ProtocolConfig(ConfigObject):
    options = {
            "disabled": BlockOption("disabled", bool, False),
            }

    def __init__(self, name=None, template=None, **kwargs):
        super().__init__()
        self.name = name

        if template is not None:
            raise NotImplementedError()

        self.options_set = {}
        for k in kwargs:
            if k not in self.options:
                raise NotImplementedError()

            self.options_set[k] = self.options[k].set(kwargs[k])

    def block_inside(self, indent):
        if len(self.options_set) == 0:
            return None

        return ("\n" + "  " * indent).join([""] + [
            f"{opt.config_text} {opt.value};" for k,opt in self.options_set.items() if opt != self.options[k]
            ])

    def __str__(self):
        inside = self.block_inside(1)
        header = f"protocol {self.protocol_type}{'' if self.name is None else ' ' + self.name }"

        if inside is None:
            return header + " {}\n"
        else:
            return header + " {" + inside + "\n}\n"

class DeviceProtocolConfig(ProtocolConfig):
    name_prefix = "device"
    protocol_type = "device"

    options = ProtocolConfig.options | {
            "scan_time":  BlockOption("scan time", int, 60),
            }
