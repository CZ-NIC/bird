import asyncio
import sys

from . import Suite

if __name__ == "__main__":
    try:
        _, cmd, suite, *args = sys.argv
    except ValueError as e:
        Suite.help(*sys.argv[1:])

    asyncio.run(Suite(suite).exec(cmd, *args))
