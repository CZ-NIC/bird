import cbor
import json
import sys

import JSON_CBOR

#print(sys.argv[1])

msg = JSON_CBOR.Message(sys.argv[1], "cbor")
with open(sys.argv[2], "w") as of:
    json.dump(msg.raw, of, indent=2)

print("OK")
