import asyncio
import re

from BIRD.Basic import Basic, BIRDException, Code

class ProtocolException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, f"Failed to parse protocol: {msg}")

class ProtocolListException(Exception):
    def __init__(self, msg):
        Exception.__init__(self, f"Failed to parse protocol list: {msg}")

class ProtocolList(Basic):
    match = {}
#    def __init__(self, **kwargs):
#        super().__init__(**kwargs)

    def register(sub):
        if sub.match in ProtocolList.match:
            raise BIRDException(f"Protocol match {sub.match} already registered for {ProtocolList.match[sub.match]}")

        ProtocolList.match[sub.match] = sub

    class UpdateState:
        def __init__(self, plist):
            self.plist = plist

            self.current = None
            self.data = {}

            self.parse_dispatch = {
                    Code.ProtocolInfo: self.parse_info,
                    Code.ProtocolDetails: self.parse_details,
                    }

        def parse_info(self, data):
            kwargs = Protocol.parse_info(data)

            if (name := kwargs["name"]) in self.data:
                raise ProtocolListException(f"Duplicate protocol {name}")

            if (m := kwargs["match"]) in self.plist.match:
                del kwargs["match"]
                kwargs["bird"] = self.plist.bird

                p = self.plist.match[m](**kwargs)
                self.data[name] = p
                self.current = p
            else:
                raise ProtocolListException(f"Unknown protocol kind {m}")

        def parse_details(self, data):
            if self.current is None:
                raise ProtocolListException(f"Protocol details without protocol: {m}")

#            print({"name":self.current.name, "data":data})
            if self.current.parse_details(data) == Protocol.LastDetail:
                self.current = None


    async def update(self):
        self.data = {}
        state = self.UpdateState(self)

        await self.bird.cli.open()
        data = await self.bird.cli.socket.command("show protocols all")

        # Get header
        if data[0]["code"] != Code.ProtocolListHeader:
            raise ProtocolListException(f"First line is not protocol list header, got {data[0]}")

        if data[0]["data"].split() != ['Name', 'Proto', 'Table', 'State', 'Since', 'Info']:
            raise ProtocolListException(f"Strange protocol list header: {data[0]['data']}")

        data.pop(0)

        if data[-1] != { "code": Code.OK, "data": "" }:
            raise ProtocolListException(f"Strange protocol list footer: {data[-1]}")

        data.pop()

        for line in data:
            state.parse_dispatch[line["code"]](line["data"])

        self.data = state.data

class Protocol(Basic):
    known_states = set(("down", "start", "up"))

    def __init__(self, name, state, last_change, info, **kwargs):
        super().__init__(**kwargs)

        self.name = name
        if state not in self.known_states:
            raise ProtocolListException(f"Strange protocol {name} state: {state}")

        self.state = state
        self.last_change = last_change
        self.info = info
        self.channels = {}

    class LastDetail:
        pass

    def parse_info(data):
        s = data.split(maxsplit=5) + [None]
        assert(len(s) <= 7)
        if len(s) < 6:
            raise ProtocolListException(f"Strange protocol info: {data}")

        s.append(None)
        s.pop(2) # drop the default table name, it's a BIRD 1 anachronism
        return dict(zip(
            ["name", "match", "state", "last_change", "info"],
            s
            ))

    def parse_details(self, data):
        if data == '':
            return Protocol.LastDetail

        if data.startswith(channel_prefix := "  Channel "):
            if (channel_name := data[len(channel_prefix):]) in self.channels:
                raise ProtocolException(f"Duplicate channel {channel_name} in {self.name}")
            c = Channel(name=channel_name, protocol=self, bird=self.bird)
            self.current_child = c
            self.channels[channel_name] = c
            return None

        if data.startswith("    "):
            if self.current_child is None:
                raise ProtocolException(f"Child details without child header in {self.name}: {data}")

            self.current_child.parse_details(data[4:])
            return None

        raise ProtocolException(f"unknown details: {data}")

    async def disable(self):
        await self.bird.cli.open()
        await self.bird.cli.socket.command(f"disable {self.name}")

    async def enable(self):
        await self.bird.cli.open()
        await self.bird.cli.socket.command(f"enable {self.name}")


class Channel(Basic):
    known_states = set(("DOWN", "START", "UP", "FLUSHING"))

    def __init__(self, name, protocol, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.protocol = protocol
        self.state = None
        self.table = None
        self.preference = None
        self.import_filter = None
        self.export_filter = None
        self.route_stats = None
        self.route_change_stats = None

        self.details_dispatch = {
                "State": self.parse_state,
                "Table": self.parse_table,
                "Preference": self.parse_preference,
                "Input filter": self.parse_import_filter,
                "Output filter": self.parse_export_filter,
                "Routes": self.parse_route_stats,
                "Route change stats": self.parse_route_change_stats_header,
                "  Import updates": lambda data: self.parse_route_change_stats_data("import updates", data),
                "  Import withdraws": lambda data: self.parse_route_change_stats_data("import withdraws", data),
                "  Export updates": lambda data: self.parse_route_change_stats_data("export updates", data),
                "  Export withdraws": lambda data: self.parse_route_change_stats_data("export withdraws", data),
                }

    def parse_details(self, data):
        k, v = data.split(":", maxsplit=1)
        self.details_dispatch[k](v.strip())

    def parse_state(self, data):
        if self.state is not None:
            raise ProtocolException(f"Duplicit channel {self.name} state in {self.protocol.name}: {data}")
        if data not in self.known_states:
            raise ProtocolException(f"Unknown channel {self.name} state in {self.protocol.name}: {data}")
        self.state = data

    def parse_table(self, data):
        if self.table is not None:
            raise ProtocolException(f"Duplicit channel {self.name} table in {self.protocol.name}: {data}")
        self.table = data

    def parse_preference(self, data):
        if self.preference is not None:
            raise ProtocolException(f"Duplicit channel {self.name} preference in {self.protocol.name}: {data}")
        self.preference = int(data)

    def parse_import_filter(self, data):
        if self.import_filter is not None:
            raise ProtocolException(f"Duplicit channel {self.name} import filter in {self.protocol.name}: {data}")
        self.import_filter = data

    def parse_export_filter(self, data):
        if self.export_filter is not None:
            raise ProtocolException(f"Duplicit channel {self.name} export filter in {self.protocol.name}: {data}")
        self.export_filter = data

    def parse_route_stats(self, data):
        if self.route_stats is not None:
            raise ProtocolException(f"Duplicit channel {self.name} route stats in {self.protocol.name}: {data}")

        if (m := re.fullmatch("(?P<imported>[0-9]+) imported, (?P<exported>[0-9]+) exported, (?P<preferred>[0-9]+) preferred", data)) is None:
            raise ProtocolException(f"Malformed route stats of channel {self.name} in {self.protocol.name}: {data}")

        self.route_stats = m.groupdict()

    def parse_route_change_stats_header(self, data):
        if self.route_change_stats is not None:
            raise ProtocolException(f"Duplicit channel {self.name} route change stats in {self.protocol.name}: {data}")

        self.route_change_stats_headers = data.split()
        self.route_change_stats = {}
#        print(self.route_change_stats_headers)

    def parse_route_change_stats_data(self, key, data):
        if self.route_change_stats is None:
            raise ProtocolException(f"Route change stats data without header in channel {self.name} in {self.protocol.name}: {data}")

        if key in self.route_change_stats:
            raise ProtocolException(f"Duplicit channel {self.name} route change stats data line {key} in {self.protocol.name}: {data}")

        d = [ None if k == "---" else int(k) for k in data.split() ]
        if len(d) != (hl := len(self.route_change_stats_headers)):
            raise ProtocolException(f"Route change data (len={len(d)}) not matching its header (len={hl}) in channel {self.name} in {self.protocol.name}: {data}")

        self.route_change_stats[key] = dict(zip(self.route_change_stats_headers, d))
#        print(key)
#        print(self.route_change_stats)


import BIRD.Protocol.Kernel
import BIRD.Protocol.Babel
import BIRD.Protocol.RAdv
