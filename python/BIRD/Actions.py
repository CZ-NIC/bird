from BIRD.Basic import Basic, Code

class Actions(Basic):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class ConfigureState:
        def __init__(self, bird):
            self.bird = bird
            self.data = {}
            self.configure_dispatch = {
                    Code.ReadingConfiguration: self.reading,
                    Code.Reconfigured: self.done,
                    }

        def reading(self, data):
            if "reading_from" in self.data:
                raise ActionException(f"Duplicit configuration file name in response: {data}")

            if not data.startswith(pfx := "Reading configuration from "):
                raise ActionException(f"Malformed configuration file name notice in response: {data}")

            self.data["reading_from"] = data[len(pfx):]

        def done(self, data):
            if "done" in self.data:
                raise ActionException(f"Reconfiguration finished twice")

            self.data["done"] = True

    async def configure(self):
        await self.bird.cli.open()
        data = await self.bird.cli.socket.command("configure")
        state = self.ConfigureState(self.bird)

        for line in data:
            state.configure_dispatch[line["code"]](line["data"])

        return state.data

