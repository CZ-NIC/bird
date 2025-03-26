import pathlib

class NetlabFlock:
    toolsdir = pathlib.Path(__file__).parent.parent
    netlabdir = toolsdir / "bird-tools" / "netlab"

if not NetlabFlock.netlabdir.exists():
    raise Exception(f"Netlab dir not found at {NetlabFlock.netlabdir.absolute()}, did you run git submodule update --init?")
