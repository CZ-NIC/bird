import re
from .CLIParser import CLIParser, subparser, ParserException

class ShowOSPFNeighborsParser(CLIParser):
    pass

@subparser(ShowOSPFNeighborsParser)
class ShowOSPFNeighborsProtocolParser(CLIParser):
    entryRegex = re.compile("^(.*):$")
    def enter(self, groups):
        self.name ,= groups

    def exit(self):
        self.parent.result[self.name] = self.result

@subparser(ShowOSPFNeighborsProtocolParser)
class ShowOSPFNeighborsHeaderParser(CLIParser):
    entryRegex = re.compile("^Router ID   	Pri	     State     	DTime	Interface  Router IP$")
    def enter(self, _):
        pass

    def exit(self):
        self.parent.result["neighbors"] = self.result

@subparser(ShowOSPFNeighborsHeaderParser)
class ShowOSPFNeighborsHeaderParser(CLIParser):
    entryRegex = re.compile("([^ ]+)\s+([^ ]+)\s+([^/]+)/([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)$")
    def enter(self, groups):
        self.id, *rest = groups
        self.result = dict(zip(
            ["priority", "state", "position", "timeout", "interface", "ip"], rest))

    def exit(self):
        self.parent.result[self.id] = self.result
