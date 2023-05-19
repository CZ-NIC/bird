from datetime import datetime
from weakref import WeakKeyDictionary

import itertools

class ConfigObject:
    def __init__(self, comment=None):
        self.symbols = {}
        self.config = WeakKeyDictionary()
        self.comment = comment

    def isp(self, indent):
        return "  " * indent

    def append(self):
        return "" if self.comment is None else f" # {self.comment}"

    def lines(self, indent):
        return [] if self.comment is None else [ f"{self.isp(indent)}# {self.comment}" ]

    def writelines(self, f):
        f.writelines([ x + "\n" for x in self.lines(0) ])

class Timestamp(ConfigObject):
    def __init__(self, comment):
        super().__init__(comment=f"{comment} at {datetime.now()}")

class BlockOption(ConfigObject):
    def __init__(self, config_text, _type, value, **kwargs):
        super().__init__(**kwargs)

        if not isinstance(value, _type):
            raise Exception("BlockOption value doesn't match declared type")

        self.config_text = config_text
        self._type = _type
        self.value = value

    def set(self, value, **kwargs):
        if value == self.value and len(kwargs) == 0:
            return self
        else:
            return type(self)(self.config_text, self._type, value, **kwargs)

    def lines(self, indent):
        return [ f"{self.isp(indent)}{self.config_text} {self.value};{self.append()}" ]

class ConfigBlock(ConfigObject):
    def __init__(self, **kwargs):
        super().__init__(**{ k:v for k,v in kwargs.items() if k not in self.options })

        self.options_set = {}
        for k,v in kwargs.items():
            if k in self.options:
                self.options_set[k] = self.options[k].set(v)

    def set(self, arg, val, **kwargs):
        if arg not in self.options:
            raise NotImplementedError

        self.options_set[arg] = self.options[arg].set(val, **kwargs)

    def lines(self, indent):
        inside = [
                (opt.lines(indent+1))
                for k,opt in self.options_set.items()
                if opt != self.options[k]
                ]

        header = self.block_header()
        isp = "  " * indent

        if len(inside) == 0:
            return [ header + " {}" + self.append() ]
        else:
            return [ *super().lines(indent), isp + header + " {", *itertools.chain(*inside), isp + "}" ]

class ProtocolConfig(ConfigBlock):
    options = {
            "disabled": BlockOption("disabled", bool, False),
            }

    def __init__(self, name=None, template=None, **kwargs):
        super().__init__(**kwargs)
        self.name = name

        if template is not None:
            raise NotImplementedError()

    def block_header(self):
        return f"protocol {self.protocol_type}{'' if self.name is None else ' ' + self.name }"

class DeviceProtocolConfig(ProtocolConfig):
    name_prefix = "device"
    protocol_type = "device"

    options = ProtocolConfig.options | {
            "scan_time":  BlockOption("scan time", int, 60),
            }
