class BIRDPrinter:
    def __init__(self, val):
        self.val = val

    @classmethod
    def lookup(cls, val):
        if val.type.code != cls.typeCode:
            return None
        if val.type.tag != cls.typeTag:
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
            "T_ENUM_RTC": "i",
            "T_ENUM_RTD": "i",
            "T_ENUM_ROA": "i",
            "T_ENUM_NETTYPE": "i",
            "T_ENUM_RA_PREFERENCE": "i",
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

def register_printers(objfile):
    objfile.pretty_printers.append(BIRDFInstPrinter.lookup)
    objfile.pretty_printers.append(BIRDFValPrinter.lookup)
    objfile.pretty_printers.append(BIRDFValStackPrinter.lookup)
    objfile.pretty_printers.append(BIRDFLineItemPrinter.lookup)
    objfile.pretty_printers.append(BIRDFLinePrinter.lookup)
    objfile.pretty_printers.append(BIRDFExecStackPrinter.lookup)

register_printers(gdb.current_objfile())

print("BIRD pretty printers loaded OK.")
