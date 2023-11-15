from yangson import DataModel

import cbor
import json

class Message:
    def __init__(self, filename, _type):
        self.filename = filename
        with open(self.filename, "rb") as sf:
            self.raw = { "json": json, "cbor": cbor }[_type].load(sf)
        
        self.dm = DataModel.from_file('yang-library.json')
        self.data = self.dm.from_raw(self.raw)
        self.data.validate()
