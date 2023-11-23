from yangson import DataModel

import cbor
import json

import os
import sys

class Message:
    def __init__(self, filename, _type):
        self.filename = filename
        with open(self.filename, "rb") as sf:
            self.raw = { "json": json, "cbor": cbor }[_type].load(sf)

        cwd = os.getcwd()
        os.chdir(os.path.dirname(sys.modules[__name__].__file__))
        self.dm = DataModel.from_file('yang-library.json')
        os.chdir(cwd)
        self.data = self.dm.from_raw(self.raw)
        self.data.validate()
