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

class ComparableDict(dict):
    def __lt__(self, other):
        if type(other) is dict:
            return self < ComparableDict(other)
        elif type(other) is ComparableDict:
            sk = sorted(list(self.keys()))
            ok = sorted(list(other.keys()))

            if sk == ok:
                for k in sk:
                    if self[k] < other[k]:
                        return True
                    if self[k] > other[k]:
                        return False

                return False
            else:
                return sk < ok
        else:
            raise TypeError("Inequality impossible between ComparableDict and non-dict")

    def __gt__(self, other):
        if type(other) is dict:
            return ComparableDict(other) < self
        else:
            return other < self

    def __le__(self, other):
        if self == other:
            return True
        else:
            return self < other

    def __ge__(self, other):
        if self == other:
            return True
        else:
            return self > other

def deep_sort_lists(a):
    if type(a) is str:
        return a
    if type(a) is int:
        return a

    try:
        return { k: deep_sort_lists(v) for k,v in a.items() }
    except AttributeError:
        return sorted([deep_sort_lists(v) for v in a ], key=lambda v: ComparableDict(v) if type(v) is dict else v)

class Differs(Exception):
    def __init__(self, a, b, tree):
        self.a = a
        self.b = b
        self.tree = tree

    @classmethod
    def false(cls, a, b, deep, tree):
        if deep:
            raise cls(a, b, tree)
        else:
            return False

def deep_eq(a, b, deep=False):
    if a == b:
        return True

    # Do not iterate over strings
    if type(a) is str and type(b) is str:
        return Differs.false(a, b, deep, tree=[])

    try:
        for k,v in a.items():
            try:
                deep_eq(v, b[k], True)
            except Differs as d:
                d.tree.append(k)
                raise d
            except KeyError:
                return Differs.false(v, None, deep, tree=[k])

        for k in b:
            if not k in a:
                return Differs.false(None, b[k], deep, tree=[k])

    except AttributeError:
        try:
            if len(a) != len(b):
                return Differs.false(len(a), len(b), deep, tree=[len])

            for i in range(len(a)):
                try:
                    deep_eq(a[i], b[i])
                except Differs as d:
                    d.tree.append(i)
                    raise d
        except TypeError:
            return Differs.false(a, b, deep, [])

    return True
