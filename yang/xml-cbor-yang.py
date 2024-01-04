import sys

import JSON_CBOR

#print(sys.argv[1])

msg = JSON_CBOR.Message(sys.argv[1], "xml")
with open(sys.argv[2], "wb") as of:
    msg.dump_cbor(of)

print("OK")
