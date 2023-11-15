from yangson import DataModel
import cbor
import json
import sys

class Message:
    def __init__(self, filename):
        self.filename = filename
        with open(self.filename) as sf:
            self.raw = json.load(sf)

        self.dm = DataModel.from_file('yang-library.json')
        self.data = self.dm.from_raw(self.raw)
        self.data.validate()

#print(sys.argv[1])

msg = Message(sys.argv[1])
#print(msg, msg.raw)
#print(cbor.dumps(msg.raw))
with open(sys.argv[2], "wb") as of:
    cbor.dump(msg.raw, of)

print("OK")
