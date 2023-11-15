import cbor
import json
import sys

import JSON_CBOR

#print(sys.argv[1])

msg = JSON_CBOR.Message(sys.argv[1], "json")
with open(sys.argv[2], "wb") as of:
    cbor.dump(msg.raw, of)

print("OK")
