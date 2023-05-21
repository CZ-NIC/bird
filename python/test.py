import asyncio
from BIRD import BIRD

async def main():
    async with BIRD("/run/bird/bird.ctl") as b:
        await b.version.update()
        print(b.version)

        await b.status.update()
        print(b.status)

        await b.protocols.update()
        print(b.protocols)

        for name, protocol in b.protocols.data.items():
            print(f"{name}: {protocol.channels}")
            for name, channel in protocol.channels.items():
                print(f"  {name}: {channel.route_change_stats}")

        print(await b.actions.configure())

        await b.protocols.update()
        print(b.protocols)

        for name, protocol in b.protocols.data.items():
            print(f"{name}: {protocol.channels}")
            for name, channel in protocol.channels.items():
                print(f"  {name}: {channel.route_change_stats}")

asyncio.run(main())
