import re

class ParserException(Exception):
    pass

def subparser(base):
    def decorator(cls):
        base.subparsers = { **base.subparsers, cls.entryRegex: cls }
        return cls
    return decorator

class CLIParser:
    subparsers = {}
    def __init__(self, groups=None, parent=None):
        self.result = {}
        self.parent = parent
        self.cur = None

        if parent is None:
            assert(groups is None)
            return

        self.enter(groups)
        print("subparser inited", self, self.result)

    def parse(self, line: str):
        print(f"in {self} parsing line {line}")
        assert(self.cur == None)
        if line is not None:
            for k,v in self.subparsers.items():
                print(f"trying to match {k} for {v}")
                if m := k.match(line):
                    self.cur = (c := v(groups=m.groups(), parent=self))
                    while c.cur is not None:
                        c = c.cur
                    return c
        elif self.parent is None:
            print("overall exit", self, self.result)
            return self

        try:
            print(f"exiting {self} with result {self.result}")
            self.exit()
            self.parent.cur = None
            return self.parent.parse(line)

        except Exception as e:
            print(f"Failed to parse line: {line}")
            raise e

    def exit(self):
        raise ParserException(f"Failed to match line to all regexes")

@subparser(CLIParser)
class VersionParser(CLIParser):
    entryRegex = re.compile("BIRD ([0-9a-z._-]+) ready.")
    def enter(self, groups):
        self.version ,= groups

    def exit(self):
        if "version" in self.parent.result:
            raise ParserException(f"Duplicate version line")

        self.parent.result["version"] = self.version

class ShowRouteParser(CLIParser):
    def __init__(self):
        super().__init__()
        self.result["tables"] = {}
        print("parser init", self, self.result)

@subparser(ShowRouteParser)
class NothingParser(CLIParser):
    entryRegex = re.compile("^$")
    def enter(self, _):
        pass

    def exit(self):
        pass

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

def parse(data: str):
    parser = ShowRouteParser()
    print("created parser", parser)
    for line in data.split("\n"):
        parser = parser.parse(line)

    parser = parser.parse(None)

    print("returning result", parser.result)
    return parser.result
