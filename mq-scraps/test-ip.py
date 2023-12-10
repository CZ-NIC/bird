import cbor2
import json

with open("test-ip.cbor", "rb") as sf:
    loaded = cbor2.load(sf)

print(loaded)
print(json.dumps(loaded))
