class BIRDPrinter:
    def __init__(self, val):
        self.val = val

    @classmethod
    def lookup(cls, val):
        t = val.type.strip_typedefs()
        if t.code != cls.typeCode:
            return None
        if t.tag != cls.typeTag:
            return None

        return cls(val)


class BIRDFValPrinter(BIRDPrinter):
    "Print BIRD\s struct f_val"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_val"

    codemap = {
            "T_INT": "i",
            "T_BOOL": "i",
            "T_PAIR": "i",
            "T_QUAD": "i",
            "T_ENUM_RTS": "i",
            "T_ENUM_BGP_ORIGIN": "i",
            "T_ENUM_SCOPE": "i",
            "T_ENUM_RTD": "i",
            "T_ENUM_ROA": "i",
            "T_ENUM_NETTYPE": "i",
            "T_ENUM_RA_PREFERENCE": "i",
            "T_ENUM_AF": "i",
            "T_IP": "ip",
            "T_NET": "net",
            "T_STRING": "s",
            "T_PATH_MASK": "path_mask",
            "T_PATH": "ad",
            "T_CLIST": "ad",
            "T_EC": "ec",
            "T_ECLIST": "ad",
            "T_LC": "lc",
            "T_LCLIST": "ad",
            "T_RD": "ec",
            "T_PATH_MASK_ITEM": "pmi",
            "T_SET": "t",
            "T_PREFIX_SET": "ti",
            }

    def to_string(self):
        code = self.val['type']
        if code.type.code != gdb.TYPE_CODE_ENUM or code.type.tag != "f_type":
            raise Exception("Strange 'type' element in f_val")

        if str(code) == "T_VOID":
            return "T_VOID"
        else:
            return "(%(c)s) %(v)s" % { "c": code, "v": self.val['val'][self.codemap[str(code)]] }

    def display_hint(self):
        return "map"

class BIRDFValStackPrinter(BIRDPrinter):
    "Print BIRD's struct f_val_stack"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_val_stack"

    def to_string(self):
        cnt = self.val['cnt']
        return ("Value stack (%(cnt)d):\n\t" % { "cnt": cnt }) + \
                "\n\t".join([ (".val[%(n) 3d] = " % { "n": n}) + str(self.val['val'][n]) for n in range(cnt-1, -1, -1) ])

    def display_hint(self):
        return "map"

class BIRDFInstPrinter(BIRDPrinter):
    "Print BIRD's struct f_inst"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_inst"

    def to_string(self):
        code = self.val['fi_code']
        if str(code) == "FI_NOP":
            return str(code) + ": " + str(self.val.cast(gdb.lookup_type("const char [%(siz)d]" % { "siz": self.val.type.sizeof })))
        return "%(code)s:\t%(lineno) 6dL\t%(size)6dS\tnext = %(next)s: .i_%(code)s = %(union)s" % {
                "code": str(code),
                "lineno": self.val['lineno'],
                "size": self.val['size'],
                "next": str(self.val['next']),
                "union": str(self.val['i_' + str(code)])
                }

# def children(self): # children iterator
    def display_hint(self):
        return "map"

class BIRDFLineItemPrinter(BIRDPrinter):
    "Print BIRD's struct f_line_item"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_line_item"

    def to_string(self):
        code = self.val['fi_code']
        if str(code) == "FI_NOP":
            return str(code) + ": " + str(self.val.cast(gdb.lookup_type("const char [%(siz)d]" % { "siz": self.val.type.sizeof })))
        return "%(code)s:\t%(lineno) 6dL\t%(flags)2dF: .i_%(code)s = %(union)s" % {
                "code": str(code),
                "lineno": self.val['lineno'],
                "flags": self.val['flags'],
                "union": str(self.val['i_' + str(code)])
                }

class BIRDFLinePrinter(BIRDPrinter):
    "Print BIRD's struct f_line"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_line"

    def to_string(self):
        cnt = self.val['len']
        return ("FLine (%(cnt)d, args=%(args)d): " % { "cnt": cnt, "args" : self.val['args'] } + \
                ", ".join([
                    ".items[%(n) 3d] = %(code)s" % {
                        "n": n,
                        "code": str(self.val['items'][n]['fi_code']),
                    } if n % 8 == 0 else str(self.val['items'][n]['fi_code']) for n in range(cnt)]))


class BIRDFExecStackPrinter(BIRDPrinter):
    "Print BIRD's struct f_exec_stack"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "f_exec_stack"

    def to_string(self):
        cnt = self.val['cnt']
        return ("Exec stack (%(cnt)d):\n\t" % { "cnt": cnt }) + \
                "\n\t".join([ ".item[%(n) 3d] = %(retflag)d V%(ventry) 3d P%(pos) 4d %(line)s" % {
                    "retflag": self.val['item'][n]['emask'],
                    "ventry": self.val['item'][n]['ventry'],
                    "pos": self.val['item'][n]['pos'],
                    "line": str(self.val['item'][n]['line'].dereference()),
                    "n": n
                        } for n in range(cnt-1, -1, -1) ])


class BIRD:
    def skip_back(t, i, v):
        if isinstance(t, str):
            t = gdb.lookup_type(t)
        elif isinstance(t, gdb.Value):
            t = gdb.lookup_type(t.string())
        elif not isinstance(t, gdb.Type):
            raise Exception(f"First argument of skip_back(t, i, v) must be a type, got {type(t)}")

        t = t.strip_typedefs()
        nullptr = gdb.Value(0).cast(t.pointer())

        if isinstance(i, gdb.Value):
            i = i.string()
        elif not isinstance(i, str):
            raise Exception(f"Second argument of skip_back(t, i, v) must be a item name, got {type(i)}")

        if not isinstance(v, gdb.Value):
            raise Exception(f"Third argument of skip_back(t, i, v) must be a value, got {type(v)}")
        if v.type.code != gdb.TYPE_CODE_PTR and v.type.code != gdb.TYPE_CODE_REF:
            raise Exception(f"Third argument of skip_back(t, i, v) must be a pointer, is {v.type} ({v.type.code})")
        if v.type.target().strip_typedefs() != nullptr[i].type:
            raise Exception(f"Third argument of skip_back(t, i, v) points to type {v.type.target().strip_typedefs()}, should be {nullptr[i].type}")

        uintptr_t = gdb.lookup_type("uintptr_t")
        taddr = v.dereference().address.cast(uintptr_t) - nullptr[i].address.cast(uintptr_t)
        return gdb.Value(taddr).cast(t.pointer())

    class skip_back_gdb(gdb.Function):
        "Given address of a structure item, returns address of the structure, as the SKIP_BACK macro does"
        def __init__(self):
            gdb.Function.__init__(self, "SKIP_BACK")

        def invoke(self, t, i, v):
            return BIRD.skip_back(t, i, v)


BIRD.skip_back_gdb()


class BIRDList:
    def __init__(self, val):
        ltype = val.type.strip_typedefs()
        if ltype.code != gdb.TYPE_CODE_UNION or ltype.tag != "list":
            raise Exception(f"Not a list, is type {ltype}")

        self.head = val["head"]
        self.tail_node = val["tail_node"]

        if str(self.head.address) == '0x0':
            raise Exception("List head is NULL")

        if str(self.tail_node["prev"].address) == '0x0':
            raise Exception("List tail is NULL")

    def walk(self, do):
        cur = self.head
        while cur.dereference() != self.tail_node:
            do(cur)
            cur = cur.dereference()["next"]


class BIRDListLength(gdb.Function):
    """Returns length of the list, as in
    print $list_length(routing_tables)"""
    def __init__(self):
        super(BIRDListLength, self).__init__("list_length")

    def count(self, _):
        self.cnt += 1

    def invoke(self, l):
        self.cnt = 0
        BIRDList(l).walk(self.count)
        return self.cnt

BIRDListLength()

class BIRDListItem(gdb.Function):
    """Returns n-th item of the list."""
    def __init__(self):
        super(BIRDListItem, self).__init__("list_item")

    class BLException(Exception):
        def __init__(self, node, msg):
            Exception.__init__(self, msg)
            self.node = node

    def count(self, node):
        if self.cnt == self.pos:
            raise self.BLException(node, "Node found")

        self.cnt += 1

    def invoke(self, l, n, t=None, item="n"):
        self.cnt = 0
        self.pos = n
        bl = BIRDList(l)
        try:
            bl.walk(self.count)
        except self.BLException as e:
            if t is None:
                return e.node
            else:
                return BIRD.skip_back(t, item, e.node)

        raise Exception("List too short")

BIRDListItem()

class BIRDResourceSize():
    def __init__(self, netto, overhead, free):
        self.netto = netto
        self.overhead = overhead
        self.free = free

    def __str__(self):
        ns = str(self.netto)
        os = str(self.overhead)
        fs = str(self.free)

        return "{: >12s} | {: >12s} | {: >12s}".format(ns, os, fs)

    def __add__(self, val):
        return BIRDResourceSize(self.netto + val.netto, self.overhead + val.overhead, self.free + val.free)

class BIRDResource():
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return f"Item {self.val.address} of class \"{self.val['class']['name'].string()}\""

    def memsize(self):
        if str(self.val["class"]["memsize"]) == '0x0':
            size = self.val["class"]["size"]
            ressize = gdb.lookup_type("struct resource").sizeof
            return BIRDResourceSize(size - ressize, ressize, 0)
        else:
            raise Exception(f"Resource class {self.val['class']['name']} with defined memsize() not known by Python")

    def parse(self):
        pass

class BIRDMBResource(BIRDResource):
    def __init__(self, val):
        self.mbtype = gdb.lookup_type("struct mblock")
        self.val = val.cast(self.mbtype)

    def memsize(self):
        return BIRDResourceSize(self.val["size"], 8 + self.mbtype.sizeof, 0)

    def __str__(self):
        return f"Standalone memory block {self.val.address} of size {self.val['size']}, data at {self.val['data'].address}"

class BIRDLinPoolResource(BIRDResource):
    def __init__(self, val):
        self.lptype = gdb.lookup_type("struct linpool")
        self.val = val.cast(self.lptype)
        self.info = None

    def count_chunk(self, which):
        cnt = 0
        chunk = self.val[which]
        while str(chunk) != '0x0':
            cnt += 1
            chunk = chunk.dereference()["next"]
        return cnt

    def parse(self):
        self.info = {
                "std_chunks": self.count_chunk("first"),
                "large_chunks": self.count_chunk("first_large"),
                }

    def memsize(self):
        if self.info is None:
            self.parse()

        overhead = (8 - 8*self.val["use_pages"]) + gdb.lookup_type("struct lp_chunk").sizeof
        return BIRDResourceSize(
                self.val["total"] + self.val["total_large"],
                (self.info["std_chunks"] + self.info["large_chunks"]) * overhead,
                0)

    def __str__(self):
        if self.info is None:
            self.parse()

        return f"Linpool {self.val.address} with {self.info['std_chunks']} standard chunks of size {self.val['chunk_size']} and {self.info['large_chunks']} large chunks"

class BIRDSlabResource(BIRDResource):
    def __init__(self, val):
        self.slabtype = gdb.lookup_type("struct slab")
        self.val = val.cast(self.slabtype)
        self.info = None

    def count_heads_item(self, item):
        self.hcnt += 1
        self.used += item.dereference().cast(self.slheadtype)["num_full"]

    def count_heads(self, which):
        self.hcnt = 0
        self.used = 0
        BIRDList(self.val[which + "_heads"]).walk(self.count_heads_item)
        self.info[which + "_heads"] = self.hcnt
        self.info[which + "_used"] = self.used
        return (self.hcnt, self.used)

    def parse(self):
        self.page_size = gdb.lookup_symbol("page_size")[0].value()
        self.slheadtype = gdb.lookup_type("struct sl_head")
        self.info = {}
        self.count_heads("empty")
        self.count_heads("partial")
        self.count_heads("full")

    def memsize(self):
        if self.info is None:
            self.parse()

        total_used = self.info["empty_used"] + self.info["partial_used"] + self.info["full_used"]
        total_heads = self.info["empty_heads"] + self.info["partial_heads"] + self.info["full_heads"]

        eff_size = total_used * self.val["obj_size"]
        free_size = self.info["empty_heads"] * self.page_size
        total_size = total_heads * self.page_size + self.slabtype.sizeof

        return BIRDResourceSize( eff_size, total_size - free_size - eff_size, free_size)

    def __str__(self):
        if self.info is None:
            self.parse()

        return f"Slab {self.val.address} " + ", ".join([
            f"{self.info[x + '_heads']} {x} heads" for x in [ "empty", "partial", "full" ]]) + \
                    f", {self.val['objs_per_slab']} objects of size {self.val['obj_size']} per head"


class BIRDPoolResource(BIRDResource):
    def __init__(self, val):
        self.pooltype = gdb.lookup_type("struct pool")
        self.resptrtype = gdb.lookup_type("struct resource").pointer()
        self.page_size = gdb.lookup_symbol("page_size")[0].value()
        self.val = val.cast(self.pooltype)
        self.items = None

    def parse_inside(self, val):
        self.items.append(BIRDNewResource(val.cast(self.resptrtype).dereference()))

    def parse(self):
        self.items = []
        BIRDList(self.val["inside"]).walk(self.parse_inside)

    def free_pages(self):
        if str(self.val['pages']) == '0x0':
            return 0
        else:
            return self.val['pages'].dereference()['free']

    def memsize(self):
        if self.items is None:
            self.parse()

        sum = BIRDResourceSize(0, self.pooltype.sizeof, self.free_pages() * self.page_size)
#        for i in self.items:
#            sum += i.memsize()

        return sum

    def __str__(self):
        if self.items is None:
            self.parse()

#        for i in self.items:
#            print(i)

        return f"Resource pool {self.val.address} \"{self.val['name'].string()}\" containing {len(self.items)} items and {self.free_pages()} free pages"

BIRDResourceMap = {
        "mbl_memsize": BIRDMBResource,
        "pool_memsize": BIRDPoolResource,
        "lp_memsize": BIRDLinPoolResource,
        "slab_memsize": BIRDSlabResource,
        }

def BIRDNewResource(res):
    cms = res["class"].dereference()["memsize"]
    for cx in BIRDResourceMap:
        if cms == gdb.lookup_symbol(cx)[0].value():
            return BIRDResourceMap[cx](res)

    return BIRDResource(res)


class BIRDResourcePrinter(BIRDPrinter):
    "Print BIRD's resource"
    typeCode = gdb.TYPE_CODE_STRUCT
    typeTag = "resource"

    def __init__(self, val):
        super(BIRDResourcePrinter, self).__init__(val)
        self.resource = BIRDNewResource(val)
        self.resource.parse()
        self.resourcetype = gdb.lookup_type("struct resource")

        if type(self.resource) == BIRDPoolResource:
            self.children = self.pool_children

    def pool_children(self):
        return iter([ ("\n", i.val.cast(self.resourcetype)) for i in self.resource.items ])

    def to_string(self):
        return f"[ {str(self.resource.memsize())} ] {str(self.resource)}"


def register_printers(objfile):
    objfile.pretty_printers.append(BIRDFInstPrinter.lookup)
    objfile.pretty_printers.append(BIRDFValPrinter.lookup)
    objfile.pretty_printers.append(BIRDFValStackPrinter.lookup)
    objfile.pretty_printers.append(BIRDFLineItemPrinter.lookup)
    objfile.pretty_printers.append(BIRDFLinePrinter.lookup)
    objfile.pretty_printers.append(BIRDFExecStackPrinter.lookup)
    objfile.pretty_printers.append(BIRDResourcePrinter.lookup)

register_printers(gdb.current_objfile())

print("BIRD pretty printers loaded OK.")
