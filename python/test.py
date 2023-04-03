import asyncio
from BIRD import BIRD

async def main():
    async with BIRD("/run/bird/bird.ctl") as b:
        await b.version.update()
        print(b.version)

        await b.status.update()
        print(b.status)

asyncio.run(main())
