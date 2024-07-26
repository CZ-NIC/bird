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

    def parse(self, line: str):
        assert(self.cur == None)
        if line is not None:
            for k,v in self.subparsers.items():
                if m := k.match(line):
                    self.cur = (c := v(groups=m.groups(), parent=self))
                    while c.cur is not None:
                        c = c.cur
                    return c
        elif self.parent is None:
            return self

        try:
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

@subparser(CLIParser)
class NothingParser(CLIParser):
    entryRegex = re.compile("^$")
    def enter(self, _):
        pass

    def exit(self):
        pass
