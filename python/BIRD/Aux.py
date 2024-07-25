import asyncio

async def dict_gather(d: dict):
    return dict(zip(d.keys(), await asyncio.gather(*d.values())))

def dict_expand(d: dict):
    out = {}
    for k,v in d.items():
        p,*r = k
        if p not in out:
            out[p] = {}
        try:
            r ,= r
        except ValueError:
            r = tuple(r)
        out[p][r] = v

    return out
