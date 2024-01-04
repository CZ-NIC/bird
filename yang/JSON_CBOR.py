from yangson import DataModel
from yangson.exceptions import InstanceValueError
from xml.etree.ElementTree import ElementTree

import ipaddress

import cbor
import json
from xml.etree.ElementTree import ElementTree

import os
import sys

class IPv6ClassTag(cbor.ClassTag):
    def __init__(self, tag_number=54, class_type=ipaddress.IPv6Address):
        super().__init__(tag_number, class_type, lambda ip: ip.packed, lambda data: ipaddress.IPv6Address(data))

cbor_transcoder = cbor.TagMapper([
    IPv6ClassTag(),
    ])

class Message:
    def __init__(self, filename, _type):
        self.filename = filename
        with open(self.filename, "rb") as sf:
            if _type == "json":
                self.raw = json.load(sf)
            elif _type == "cbor":
                self.raw = cbor_transcoder.load(sf)
            elif _type == "xml":
                self.xml = ElementTree()
                self.xml.parse(sf)
            else:
                raise Exception()

        cwd = os.getcwd()
        os.chdir(os.path.dirname(sys.modules[__name__].__file__))
#        self.dm = DataModel.from_file('yang-library.json', [".", "/usr/share/yang/modules/libyang/"])
        self.dm = DataModel.from_file('yang-library.json', ["."])
        print(self.dm, type(self.dm))
        at = self.dm.get_schema_node("test_ip:message/address").type
        ft = self.dm.get_schema_node("test_ip:message/foo").type
        print(at, type(at), at.types)
        print(ft, type(ft))
        os.chdir(cwd)
        if _type == "xml":
            self.data = self.dm.from_xml(self.xml.getroot())
        else:
            self.data = self.dm.from_raw(self.raw)
        print(self.data, type(self.data))
        t = self.data["test_ip:message"]["address"]
        print(t, type(t))
        self.data.validate()

    def unnodify(cls, what):
        print("unnodify", what, type(what))
        try:
            return { i: cls.unnodify(what[i]) for i in what }
        except InstanceValueError as e:
            if str(e).endswith(" is a scalar instance"):
                return what.value
            raise e

    def dump_cbor(self, file, **kwargs):
        cbor_transcoder.dump(self.unnodify(self.data), file, **kwargs)

    def dump_json(self, file, **kwargs):
        json.dump(self.data.raw_value(), file, **kwargs)

    def dump_xml(self, file):
        et = ElementTree(self.data.to_xml())
        et.write(file, encoding="unicode")
