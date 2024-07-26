import re
from .CLIParser import CLIParser, subparser, ParserException

class ShowRouteParser(CLIParser):
    def __init__(self):
        super().__init__()
        self.result["tables"] = {}

@subparser(ShowRouteParser)
class TableParser(CLIParser):
    entryRegex = re.compile("^Table (.*):$")
    def enter(self, groups):
        self.name ,= groups
        self.result["networks"] = {}

    def exit(self):
        if self.name in self.parent.result["tables"]:
            raise ParserException(f"Duplicate table name")

        self.parent.result["tables"][self.name] = self.result

@subparser(TableParser)
class NetworkParser(CLIParser):
    entryRegex = re.compile("([0-9a-f:.]+/[0-9]+)(\\s+.*)")
    def enter(self, groups):
        self.network, rest = groups
        self.result["routes"] = []
        self.parse(rest)

    def exit(self):
        self.parent.result["networks"][self.network] = self.result

@subparser(NetworkParser)
class RouteParser(CLIParser):
    entryRegex = re.compile("\\s+(unicast|unreachable) \\[(.*) ((?:[0-9]{2}:){2}[0-9]{2}\\.[0-9]{3})\\] (.*)")
    def enter(self, groups):
        self.result = {
                k: v for k,v in zip(("dest", "proto", "when", "args"), groups)
                }
        if self.result["dest"] == "unicast":
            self.result["nexthop"] = []

    def exit(self):
        self.parent.result["routes"].append(self.result)

@subparser(RouteParser)
class NextHopParser(CLIParser):
    entryRegex = re.compile("\\s+via ([0-9a-f:.]+) on (.*)")
    def enter(self, groups):
        self.result = {
                k: v for k,v in zip(("nexthop", "iface"), groups)
                }

    def exit(self):
        self.parent.result["nexthop"].append(self.result)

@subparser(RouteParser)
class DevNextHopParser(CLIParser):
    entryRegex = re.compile("\\s+dev ([^:]*)")
    def enter(self, groups):
        self.iface ,= groups

    def exit(self):
        self.parent.result["nexthop"].append({ "iface": self.iface })

@subparser(RouteParser)
class AttributeParser(CLIParser):
    entryRegex = re.compile("\\s+([a-zA-Z_.0-9]+): (.*)$")
    def enter(self, groups):
        self.key, self.value = groups

    def exit(self):
        if self.key in self.parent.result:
            raise ParserException(f"Duplicate key {self.key} in route")
        self.parent.result[self.key] = self.value

@subparser(RouteParser)
class InternalRouteHandlingValuesParser(CLIParser):
    entryRegex = re.compile("\\s+Internal route handling values: (\\d+)L (\\d+)G (\\d+)S id (\\d+)$")
    def enter(self, groups):
        self.result = {
                k: v for k,v in zip(("!_l", "!_g", "!_s", "!_id"), groups)
                }

    def exit(self):
        for k,v in self.result.items():
            if k in self.parent.result:
                raise ParserException(f"Duplicate internal value {k} in route")
            self.parent.result[k] = v
